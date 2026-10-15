import hashlib
import hmac
import logging
import os
import socket
import struct
import threading
from abc import ABC

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .iptools import int_to_ip

# Runtime compression support
try:
    import zlib as _real_zlib
    _zlib_available = True
except ImportError:
    _zlib_available = False

# Start with compression disabled (no-op)
from types import SimpleNamespace


class CompressionState:
    """Per-connection compression configuration.

    Each Client/Server owns its own instance so multiple connections with
    different compression settings can coexist in the same process without
    stomping on each other's packet serialization (the old module-global
    approach was not thread-safe).
    """
    __slots__ = ("enabled", "level")

    def __init__(self, enabled: bool = False, level: int = 6):
        self.enabled = bool(enabled)
        self.level = max(1, min(9, level))

    def compress(self, data: bytes) -> bytes:
        if self.enabled and _zlib_available:
            return _real_zlib.compress(data, self.level)
        return data

    def decompress(self, data: bytes) -> bytes:
        if self.enabled and _zlib_available:
            return _real_zlib.decompress(data)
        return data


# Module-level default used when no explicit CompressionState is passed to
# Packet.to_bytes()/from_socket() (backward compatibility).
_default_compression = CompressionState()

# Backward-compat global namespace whose behavior mirrors _default_compression.
zlib = SimpleNamespace()
compression_enabled = False
compression_level = 6

# Backward-compat alias (read-only)
ENABLE_COMPRESSION = False


def _refresh_default_compression():
    global zlib, compression_enabled, compression_level, ENABLE_COMPRESSION
    zlib.compress = _default_compression.compress
    zlib.decompress = _default_compression.decompress
    compression_enabled = _default_compression.enabled
    compression_level = _default_compression.level
    ENABLE_COMPRESSION = _default_compression.enabled


_refresh_default_compression()


def set_compression(enabled: bool, level: int = 6):
    """Enable or disable zlib compression for the module-level default state.
    Affects Packet.to_bytes()/from_socket() calls that don't pass an explicit
    CompressionState. Prefer a per-connection CompressionState for new code.
    """
    _default_compression.enabled = bool(enabled)
    _default_compression.level = max(1, min(9, level))
    _refresh_default_compression()

# region PacketTypes
MSG = 0x01  # Message
PING = 0x02  # Ping
# -----     Client       -----#
S2C = 0x03  # Send to client
GCL = 0x04  # Get clients list
FN = 0x05  # Run function
SD = 0x06  # Server data
RQIP = 0x07  # Request IP
GSI = 0x08  # Get self-info (client will get info about itself)
# -----  Server Answers  -----#
SA = 0x10  # Server answer
EXIT = 0x11  # Exit
ERR = 0x12  # Error
AIP = 0x13  # Assign IP
HSK = 0x14  # Handshake
HC2C = 0x15  # Handshake to client prefix
BCST = 0x16  # Broadcast (admin only)
AUTH = 0x17  # Authenticate (admin token)
ADMIN = 0x18  # Admin command / response
CLIENT_INFO = 0x19  # Client info (hash, metadata)
MPAK = 0x1A  # Multi-packet aggregation (bundle multiple packets into one)

packetTypes = {
    MSG: "MSG", PING: "PING",
    S2C: "S2C", GCL: "GCL",
    FN: "FN", SD: "SD",
    RQIP: "RQIP", SA: "SA",
    EXIT: "EXIT", ERR: "ERR",
    AIP: "AIP", HSK: "HSK",
    HC2C: "HC2C", GSI: "GSI",
    BCST: "BCST", AUTH: "AUTH",
    ADMIN: "ADMIN", CLIENT_INFO: "CLIENT_INFO",
    MPAK: "MPAK"
}
_ = {}
for k, v in packetTypes.items():
    _[v] = k
packetTypes = packetTypes | _
del _

encryptedTypes = {
    S2C
}


class ClientExitCodes:
    """Codes that user gives to server (or opposite) when EXIT packet"""
    """close without reason"""
    ClientClosed = b"CC"
    """Process exited"""
    ProcessExit = b"EX"
    """Unexpected error"""
    UnexpectedError = b"UE"


class ERR_CODES:
    FNF = 0x01
    FF = 0x02
    S2CF = 0x03
    RQIPF = 0x04
    SDF = 0x05
    GCLF = 0x06
    AIPF = 0x07
    HSKF = 0x08
    UKNP = 0x09
    UNREACHABLE = 0x0A  # Client unreachable

    code_to_error = {
        FNF: "Function not found",
        FF: "Function failed",
        S2CF: "S2C failed",
        RQIPF: "RQIP failed",
        SDF: "SD failed",
        GCLF: "Get clients list failed",
        AIPF: "Assign IP failed",
        HSKF: "Handshake failed",
        UKNP: "Unknown packet type",
        UNREACHABLE: "Client unreachable"
    }

    def __getitem__(self, key):
        return self.code_to_error[key]


# endregion

GCM_NONCE_SIZE = 12  # For encryption
MAC_SIZE = 32  # HMAC-SHA256 size

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)


def recv_exact(sock, size: int) -> bytes | None:
    if sock is None:
        return None
    buf = b''
    while len(buf) < size:
        part = sock.recv(size - len(buf))
        if not part:
            return None
        buf += part
    return buf


def recv_packet_raw(sock):
    """Read a packet from socket without decompression.
    Used for AIP/HSK handshake packets which are sent uncompressed.
    Returns Packet with raw (uncompressed) payload.
    """
    header = recv_exact(sock, 5)
    if not header:
        return None
    type_, length = struct.unpack(">BI", header)
    data = recv_exact(sock, length)
    if data is None:
        return None
    if type_ == S2C:
        if len(data) < 8:
            return None
        dst_ip = struct.unpack(">I", data[:4])[0]
        src_ip = struct.unpack(">I", data[4:8])[0]
        return Packet(type_, data[8:], dst_ip=dst_ip, src_ip=src_ip)
    return Packet(type_, data)


def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypts data using AES-GCM.
    :return: nonce (12) + ciphertext + tag (16)"""
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes")

    # Generate random nonce (12 bytes)
    nonce = get_random_bytes(GCM_NONCE_SIZE)

    # Encrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Format: nonce (12) + ciphertext + tag (16)
    return nonce + ciphertext + tag


def decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypts data using AES-GCM.
    :return: data (bytes)"""
    if len(data) < GCM_NONCE_SIZE + 16:
        raise ValueError("Invalid ciphertext (too short)")

    # Split nonce, ciphertext and tag
    nonce = data[:GCM_NONCE_SIZE]
    ciphertext = data[GCM_NONCE_SIZE:-16]
    tag = data[-16:]

    # Decrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        raise ValueError("Decryption failed: invalid tag or corrupted data") from e


def get_client_hash() -> str:
    """Generate a stable client *identifier* from system hardware info.

    Uses MAC address, hostname, and machine ID, hashed with SHA256. This is an
    identifier, NOT a secret: it is deterministic and anyone who knows the same
    hardware facts can reproduce it. Do not treat it as an authentication
    credential. It also encodes machine-identifying data, so avoid sharing it.
    """
    import platform
    import uuid
    mac = uuid.getnode()
    hostname = socket.gethostname()
    machine_id = ""
    try:
        if platform.system() == "Windows":
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography"
            ) as key:
                machine_id = winreg.QueryValueEx(key, "MachineGuid")[0]
        else:
            for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                if os.path.exists(p):
                    with open(p) as f:
                        machine_id = f.read().strip()
                    break
    except Exception:
        pass
    raw = f"{mac:x}:{hostname}:{machine_id}"
    return hashlib.sha256(raw.encode()).hexdigest()


ADMIN_TOKEN_PREFIX = "pbkdf2_sha256"
ADMIN_TOKEN_ITERATIONS = 200_000


def _admin_token_salt(username: str) -> bytes:
    """Deterministic per-user salt.

    A deterministic salt keeps ``generate_admin_token`` reproducible so the
    ``--login user pass`` flow and configured tokens keep matching, while still
    defeating global precomputed (rainbow) tables.
    """
    return hashlib.sha256(f"dosp-admin-salt:{username}".encode()).digest()[:16]


def generate_admin_token(username: str, password: str, salt: bytes | None = None) -> str:
    """Generate a salted, slow-hashed admin token from username and password.

    Format: ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``.

    PBKDF2-HMAC-SHA256 with a per-user salt is used instead of a bare SHA256,
    so a leaked token file cannot be cracked with precomputed tables.
    """
    if salt is None:
        salt = _admin_token_salt(username)
    raw = f"{username}:{password}".encode()
    dk = hashlib.pbkdf2_hmac("sha256", raw, salt, ADMIN_TOKEN_ITERATIONS)
    return f"{ADMIN_TOKEN_PREFIX}${ADMIN_TOKEN_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_admin_token(token: str, stored: str) -> bool:
    """Constant-time verification of an admin token against a stored value.

    Accepts either the stored token string itself (bearer model, what
    ``generate_admin_token`` returns and the client sends) or the raw
    ``username:password`` secret (which is re-derived and compared). Legacy
    plain tokens (random hex) are compared directly. All comparisons are
    constant-time.
    """
    if not token or not stored:
        return False
    # Bearer model: the configured token is presented verbatim.
    if hmac.compare_digest(token, stored):
        return True
    # Password model: derive from the presented secret and compare.
    if stored.startswith(ADMIN_TOKEN_PREFIX + "$"):
        try:
            _, iterations, salt_hex, hash_hex = stored.split("$", 3)
            dk = hashlib.pbkdf2_hmac(
                "sha256", token.encode(), bytes.fromhex(salt_hex), int(iterations)
            )
            return hmac.compare_digest(dk.hex(), hash_hex)
        except Exception:
            return False
    return False


def derive_tunnel_keys(shared_secret: bytes, info: bytes = b'dosp-c2c-v1') -> dict:
    """
    Derive multiple keys from shared secret (similar to TLS PRF).
    Returns encryption key, MAC key, and IV material.
    """
    # Derive 96 bytes: 32 encryption + 32 mac + 32 iv_material
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=96,
        salt=None,
        info=info
    ).derive(shared_secret)

    return {
        'encryption': key_material[:32],
        'mac': key_material[32:64],
        'iv_material': key_material[64:96]
    }


class Packet:
    def __init__(self, type_: int, payload: bytes, dst_ip: int = None, src_ip: int = None, encryption_key=None):
        self.type = type_
        self.payload = payload
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.encryption_key = encryption_key
        self._cached_bytes = None
        self._cached_key = None

    def clear_cache(self):
        self._cached_bytes = None
        self._cached_key = None

    def _serialize_sub(self) -> bytes:
        """Serialize packet body for MPAK sub-packet (no compression, raw format)."""
        if self.type == S2C:
            dst_bytes = struct.pack(">I", self.dst_ip)
            src_bytes = struct.pack(">I", self.src_ip or 0)
            payload = dst_bytes + src_bytes + self.payload
        else:
            payload = self.payload
        header = struct.pack(">BI", self.type, len(payload))
        return header + payload

    @staticmethod
    def multi(packets: list['Packet']) -> 'Packet':
        """Create a multi-packet (MPAK) from a list of packets.
        All sub-packets are serialized without compression, then
        compressed together as one payload when to_bytes() is called.
        """
        raw = b''.join(p._serialize_sub() for p in packets)
        return Packet(MPAK, raw)

    def unpack(self) -> list['Packet']:
        """Unpack an MPAK packet into individual Packet objects.
        Only valid for MPAK type packets.
        """
        if self.type != MPAK:
            raise ValueError(
                f"Packet is not MPAK (type={packetTypes.get(self.type, hex(self.type))})"
            )
        data = self.payload
        packets = []
        offset = 0
        while offset + 5 <= len(data):
            sub_type = data[offset]
            length = struct.unpack(">I", data[offset+1:offset+5])[0]
            offset += 5
            if offset + length > len(data):
                break
            payload = data[offset:offset+length]
            offset += length
            if sub_type == S2C:
                dst_ip = struct.unpack(">I", payload[:4])[0] if len(payload) >= 8 else 0
                src_ip = struct.unpack(">I", payload[4:8])[0] if len(payload) >= 8 else 0
                packets.append(Packet(sub_type, payload[8:], dst_ip=dst_ip, src_ip=src_ip))
            else:
                packets.append(Packet(sub_type, payload))
        return packets

    def to_bytes(self, compression: CompressionState | None = None) -> bytes:
        if compression is None:
            compression = _default_compression
        # Encrypted packets must never be cached: re-encoding must produce a
        # fresh AES-GCM nonce. Caching them (or reusing cached ciphertext across
        # sends) risks catastrophic nonce reuse if the plaintext ever changes.
        cacheable = self.encryption_key is None
        cache_key = (id(compression), compression.enabled, compression.level)
        if cacheable and self._cached_bytes is not None and self._cached_key == cache_key:
            return self._cached_bytes

        if self.type == S2C:
            if self.dst_ip is None:
                raise ValueError("dst_ip required for type S2C")
            payload = self.payload
            if self.encryption_key is not None:
                # Encrypt into a local variable; do not mutate self.payload.
                payload = encrypt(payload, self.encryption_key)
            dst_bytes = struct.pack(">I", self.dst_ip)
            src_bytes = struct.pack(">I", self.src_ip or 0)

            # compress only data (destination, src ip and payload)
            pre_payload = dst_bytes + src_bytes + payload
            total_payload = compression.compress(pre_payload)
            header = struct.pack(">BI", self.type, len(total_payload))
            result = header + total_payload
        else:
            payload = compression.compress(self.payload)
            header = struct.pack(">BI", self.type, len(payload))
            result = header + payload

        if cacheable:
            self._cached_bytes = result
            self._cached_key = cache_key
        return result

    @staticmethod
    def from_socket(sock, src_ip: int = None, raise_on_error: bool = False,
                    compression: CompressionState | None = None) -> 'Packet | None':
        """
        Read a single packet off the wire.

        Note: C2C/tunneled payloads are NOT decrypted here. For S2C the first
        8 bytes are the routing header, and tunnel decryption is performed by
        ``TunneledClient.decrypt`` once the routing header has been stripped.

        :raises PacketError
        :raises VNetError
        """
        if compression is None:
            compression = _default_compression
        header = recv_exact(sock, 5)
        if not header:
            if raise_on_error:
                raise VNetError("failed to receive packet header")
            return None

        type_, length = struct.unpack(">BI", header)  # is not compressed
        data = recv_exact(sock, length)

        if data is None:
            if raise_on_error:
                raise VNetError("failed to receive packet data")
            return None
        data = compression.decompress(data)

        if type_ == S2C:
            if len(data) < 8:
                if raise_on_error:
                    raise VNetError("invalid S2C packet (missing dst/src header)")
                return None
            dst_ip = struct.unpack(">I", data[:4])[0]
            parsed_src_ip = struct.unpack(">I", data[4:8])[0]
            payload = data[8:]
            # prefer parsed src for S2C
            return Packet(type_, payload, dst_ip=dst_ip, src_ip=parsed_src_ip)

        return Packet(type_, data, src_ip=src_ip)

    def size(self):
        return len(self.to_bytes())

    def __str__(self) -> str:
        type_name = packetTypes.get(self.type, hex(self.type))
        base = f"type={type_name}, payload={self.payload[:50]}{'...' if len(self.payload) > 50 else ''}, encrypted={self.encryption_key is not None}"
        extra = []
        if self.dst_ip is not None:
            extra.append(f"dst_ip={int_to_ip(self.dst_ip)}")
        if self.src_ip is not None:
            extra.append(f"src_ip={int_to_ip(self.src_ip)}")
        if extra:
            return f"Packet({base}, {', '.join(extra)})"
        return f"Packet({base})"


class IClient(ABC):

    def send(self, pkt: Packet) -> None:
        raise NotImplementedError

    def receive(self) -> Packet | None:
        raise NotImplementedError


class RemoteClient(IClient):
    def __init__(self, sock: socket.socket | None,
                 ip: int, logger: logging.Logger,
                 allow_local=False,
                 encryption_key=None,
                 compression: CompressionState | None = None) -> None:
        if not allow_local and sock is None:
            raise HandshakeError("local connection not allowed")

        self.sock = sock
        self.ip = ip
        self.logger = logger
        self.compression = compression
        # Serializes writes from the per-client handler thread and from server
        # broadcasts / disconnect notifications so frames don't interleave.
        self._send_lock = threading.Lock()
        self.message_queue: list[Packet] = []
        self.should_disconnect = False

        self.encryption_key = encryption_key
        if encryption_key is not None:
            self.encryption_completed = len(encryption_key) == 32
        else:
            self.encryption_completed = False

        # Admin & identity fields
        self.is_admin: bool = False
        self.client_hash: str = ""
        self.connected_at: float = 0.0
        self.packets_received: int = 0
        self.packets_sent: int = 0

        # Exit metadata captured from an EXIT packet, reported once by the
        # connection handler so a clean exit is not double-notified.
        self.exit_code: str = ""
        self.exit_reason: str | None = None

    def send(self, pkt: Packet) -> None:
        if self.sock is not None:
            data = pkt.to_bytes(self.compression)
            with self._send_lock:
                self.sock.sendall(data)
        else:
            self.message_queue.append(pkt)

    def receive(self) -> Packet | None:
        if self.sock is not None:
            return Packet.from_socket(self.sock, compression=self.compression)
        if self.message_queue:
            return self.message_queue.pop(0)
        return None


class TunneledClient(IClient):
    """
    Production-ready C2C tunnel with TLS-inspired security:
    - Diffie-Hellman key exchange (X25519)
    - Separate encryption and MAC keys
    - Sequence numbers to prevent replay attacks
    - Message authentication codes (HMAC)
    """

    def __init__(self, ip: int, logger: logging.Logger,
                 encryption_key=None, sock: socket.socket | None = None,
                 use_dh: bool = False, private_key=None,
                 compression: CompressionState | None = None,
                 send_lock=None):
        self.sock = sock
        self.ip = ip
        self.logger = logger
        self.compression = compression
        # Shared with the owning Client so concurrent sends cannot interleave
        # partial frames on the single connection socket.
        self.send_lock = send_lock
        self.message_queue = []  # For local communication

        # Security parameters
        self.use_dh = use_dh  # Use Diffie-Hellman key exchange
        self.private_key = private_key  # For DH exchange
        self.encryption_key = None
        self.mac_key = None
        self.iv_material = None

        # Sequence numbers for replay protection
        self.send_sequence = 0
        self.recv_sequence = 0

        # Legacy support: if encryption_key provided, use it directly
        if encryption_key is not None:
            if len(encryption_key) != 32:
                raise ValueError(f"Invalid encryption key length: {len(encryption_key)}")
            # New format: derive keys from shared secret
            keys = derive_tunnel_keys(encryption_key)
            self.encryption_key = keys['encryption']
            self.mac_key = keys['mac']
            self.iv_material = keys['iv_material']
            self.encryption_completed = True
        else:
            self.encryption_completed = False

    def __repr__(self):
        status = "completed" if self.encryption_completed else "pending"
        return f"Tunnel(ip={int_to_ip(self.ip)}, status={status}, dh={self.use_dh})"

    def _create_authenticated_message(self, data: bytes) -> bytes:
        """
        Create message with encryption + authentication (TLS-inspired).
        Format: [sequence(8)] + [encrypted_data] + [mac(32)]
        """
        if not self.encryption_completed:
            raise ValueError("Cannot send: encryption not completed")

        # Increment sequence number
        self.send_sequence += 1
        seq_bytes = self.send_sequence.to_bytes(8, 'big')

        # Prepend sequence to data before encryption
        message = seq_bytes + data

        # Encrypt: returns nonce(12) + ciphertext + tag(16)
        ciphertext = encrypt(message, self.encryption_key)

        # Add HMAC for integrity: MAC(sequence + ciphertext)
        mac = hmac.new(
            self.mac_key,
            seq_bytes + ciphertext,
            hashlib.sha256
        ).digest()

        # Final format: ciphertext + mac
        return ciphertext + mac

    def _verify_and_decrypt_message(self, data: bytes) -> bytes:
        """
        Verify MAC and decrypt message.
        Expected format: [encrypted_data] + [mac(32)]
        """
        if not self.encryption_completed:
            raise ValueError("Cannot receive: encryption not completed")

        if len(data) < MAC_SIZE + GCM_NONCE_SIZE + 16:  # mac + nonce + min_ciphertext + tag
            raise ValueError("Message too short")

        # Split ciphertext and MAC
        ciphertext = data[:-MAC_SIZE]
        received_mac = data[-MAC_SIZE:]

        # Expected sequence number
        expected_seq = self.recv_sequence + 1
        seq_bytes = expected_seq.to_bytes(8, 'big')

        # Verify MAC
        expected_mac = hmac.new(
            self.mac_key,
            seq_bytes + ciphertext,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(received_mac, expected_mac):
            raise ValueError("MAC verification failed - message tampered or wrong sequence")

        # Decrypt
        decrypted = decrypt(ciphertext, self.encryption_key)

        # Extract and verify sequence number
        message_seq = int.from_bytes(decrypted[:8], 'big')
        if message_seq != expected_seq:
            raise ValueError(f"Sequence mismatch: expected {expected_seq}, got {message_seq}")

        # Update receive sequence
        self.recv_sequence = message_seq

        # Return data without sequence number
        return decrypted[8:]

    def send(self, pkt: Packet) -> None:
        """Send packet through encrypted and authenticated tunnel"""
        if not self.encryption_completed:
            self.logger.warning("TunneledClient.send called before encryption completed")
            return

        try:
            # Create authenticated message
            authenticated_data = self._create_authenticated_message(pkt.payload)

            # Create encrypted packet
            encrypted_pkt = Packet(pkt.type, authenticated_data, pkt.dst_ip, pkt.src_ip)

            if self.sock is not None:
                data = encrypted_pkt.to_bytes(self.compression)
                if self.send_lock is not None:
                    with self.send_lock:
                        self.sock.sendall(data)
                else:
                    self.sock.sendall(data)
            else:
                # For local communication
                self.message_queue.append(encrypted_pkt)

            self.logger.debug(f"Sent authenticated message (seq={self.send_sequence}) to {int_to_ip(self.ip)}")

        except Exception as e:
            self.logger.error(f"Failed to encrypt and send packet: {e}")
            raise

    def recv(self) -> Packet | None:
        """Receive packet from encrypted and authenticated tunnel"""
        if not self.encryption_completed:
            self.logger.warning("TunneledClient.recv called before encryption completed")
            return None

        try:
            if self.sock is not None:
                raw_pkt = Packet.from_socket(self.sock, compression=self.compression)
                if raw_pkt is None:
                    return None
            else:
                # For local communication
                if not self.message_queue:
                    return None
                raw_pkt = self.message_queue.pop(0)

            # Verify and decrypt
            decrypted_payload = self._verify_and_decrypt_message(raw_pkt.payload)

            self.logger.debug(f"Received authenticated message (seq={self.recv_sequence}) from {int_to_ip(self.ip)}")

            return Packet(raw_pkt.type, decrypted_payload, raw_pkt.dst_ip, raw_pkt.src_ip)

        except Exception as e:
            self.logger.error(f"Failed to receive and decrypt packet: {e}")
            return None

    def decrypt(self, pkt: Packet) -> Packet:
        """Decrypt packet that was received through server"""
        if not self.encryption_completed:
            return pkt

        try:
            decrypted_payload = self._verify_and_decrypt_message(pkt.payload)
            return Packet(pkt.type, decrypted_payload, pkt.dst_ip, pkt.src_ip)
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise


class VNetError(Exception):
    preset = "{}"

    def __init__(self, msg: str, core_error: str | None = None):
        self.core_error = core_error
        super().__init__(self.preset.format(msg))


class PacketError(VNetError):
    preset = "Packet error: {}"


class HandshakeError(VNetError):
    preset = "Handshake error: {}"


__all__ = [
              'Packet', 'recv_exact', 'recv_packet_raw',
              'ERR_CODES', 'VNetError', 'HandshakeError', 'PacketError',
              "encrypt", "decrypt", "RemoteClient", "TunneledClient",
              "encryptedTypes", "packetTypes", "ClientExitCodes",
              "derive_tunnel_keys", "MAC_SIZE", "GCM_NONCE_SIZE",
              "get_client_hash", "generate_admin_token", "verify_admin_token",
              "CompressionState"
          ] + [x for x in packetTypes.keys() if not isinstance(x, int)]
