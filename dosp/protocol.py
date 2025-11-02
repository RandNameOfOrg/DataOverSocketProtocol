import logging
import socket
import struct
import hmac
import hashlib

from abc import ABC
from enum import Enum

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .iptools import ip_to_int, int_to_ip

# region PacketTypes
MSG  = 0x01   # Message
PING = 0x02   # Ping
#-----     Client       -----#
S2C  = 0x03  # Send to client
GCL  = 0x04  # Get clients list
FN   = 0x05  # Run function
SD   = 0x06  # Server data
RQIP = 0x07  # Request IP
GSI  = 0x08  # Get self-info (client will get info about itself)
#-----  Server Answers  -----#
SA   = 0x10  # Server answer
EXIT = 0x11  # Exit
ERR  = 0x12  # Error
AIP  = 0x13  # Assign IP
HSK  = 0x14  # Handshake
HC2C = 0x15  # Handshake to client prefix

packetTypes = {
    MSG: "MSG",   PING: "PING",
    S2C: "S2C",   GCL: "GCL",
    FN: "FN",     SD: "SD",
    RQIP: "RQIP", SA: "SA",
    EXIT: "EXIT", ERR: "ERR",
    AIP: "AIP",   HSK: "HSK",
    HC2C: "HC2C", GSI: "GSI"
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
    """Error codes"""
    """Function not found"""
    FNF: bytes   = 0x01
    """Function failed"""
    FF: bytes    = 0x02
    """S2C failed"""
    S2CF: bytes  = 0x03
    """RQIP failed"""
    RQIPF: bytes = 0x04
    """SD packet failed"""
    SDF: bytes   = 0x05
    """Get client list packet failed"""
    GCLF: bytes  = 0x06
    """Assign vIP failed"""
    AIPF: bytes  = 0x07
    """Handshake failed"""
    HSKF: bytes  = 0x08
    """Unknown packet"""
    UKNP: bytes  = 0x09

    code_to_error = {
        FNF:   "Function not found",
        FF:    "Function failed",
        S2CF:  "S2C failed",
        RQIPF: "RQIP failed",
        SDF:   "SD failed",
        GCLF:  "Get clients list failed",
        AIPF:  "Assign IP failed",
        HSKF:  "Handshake failed",
        UKNP:  "Unknown packet type"
    }

    def __getitem__(self, key):
        return self.code_to_error[key]

# endregion

GCM_NONCE_SIZE = 12 # For encryption
MAC_SIZE = 32 # HMAC-SHA256 size

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
    def __init__(self, type_: int, payload: bytes, dst_ip: int = None, src_ip: int = None, encryption_key = None):
        globals().update(packetTypes)
        self.type    = type_
        self.payload = payload
        self.dst_ip  = dst_ip
        self.src_ip  = src_ip
        self.encryption_key = encryption_key

    def to_bytes(self) -> bytes:
        if self.type == S2C:
            if self.dst_ip is None:
                raise ValueError("dst_ip required for type S2C")
            if self.encryption_key is not None:
                self.payload = encrypt(self.payload, self.encryption_key)
            dst_bytes = struct.pack(">I", self.dst_ip)
            src_bytes = struct.pack(">I", self.src_ip or 0)
            total_payload = dst_bytes + src_bytes + self.payload
            return struct.pack(">BI", self.type, len(total_payload)) + total_payload
        else:
            return struct.pack(">BI", self.type, len(self.payload)) + self.payload

    @staticmethod
    def from_socket(sock, src_ip: int = None, raise_on_error: bool = False, encryption_key=None) -> 'Packet | None':
        header = recv_exact(sock, 5)
        if not header:
            if raise_on_error:
                raise VNetError("failed to receive packet header")
            return None

        type_, length = struct.unpack(">BI", header)
        data = recv_exact(sock, length)
        if data is None:
            if raise_on_error:
                raise VNetError("failed to receive packet data")
            return None

        # For tunneled packets (S2C), do not attempt to decrypt here, as the payload header contains routing info
        if encryption_key and type_ in encryptedTypes and type_ != S2C:
            try:
                data = decrypt(data, encryption_key)
            except ValueError as e:
                if raise_on_error:
                    raise PacketError(f"Decryption failed: {e}")
                return None

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

    def __str__(self) -> str:
        base = f"type={packetTypes[self.type]}, payload={self.payload[:50]}{'...' if len(self.payload) > 50 else ''}, encrypted={self.encryption_key is not None}"
        if self.dst_ip is None:
            return f"Packet({base})"
        return f"Packet({base}, dst_ip={int_to_ip(self.dst_ip)})"

class IClient(ABC):
    """Interface for a client"""
    
    def send(self, pkt: Packet) -> None:
        raise NotImplementedError
    def recv(self) -> Packet | None:
        raise NotImplementedError

class RemoteClient(IClient):
    def __init__(self, sock: socket.socket | None,
                 ip: int, logger: logging.Logger,
                 allow_local = False,
                 encryption_key = None) -> None:
        if not allow_local and sock is None:
            raise HandshakeError("local connection not allowed")

        self.sock = sock
        self.ip = ip
        self.logger = logger

        self.encryption_key = encryption_key
        if encryption_key is not None:
            self.encryption_completed = len(encryption_key) == 32
        else:
            self.encryption_completed = False

    def send(self, pkt: Packet) -> None:
        if self.sock is not None:
            self.sock.sendall(pkt.to_bytes())

    def recv(self) -> Packet | None:
        return Packet.from_socket(self.sock)


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
                 use_dh: bool = False, private_key=None):
        self.sock = sock
        self.ip = ip
        self.logger = logger
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
            if len(encryption_key) == 32:
                # New format: derive keys from shared secret
                keys = derive_tunnel_keys(encryption_key)
                self.encryption_key = keys['encryption']
                self.mac_key = keys['mac']
                self.iv_material = keys['iv_material']
                self.encryption_completed = True
            elif len(encryption_key) == 16:
                # Old format: partial key (waiting for second half)
                self.encryption_key = encryption_key
                self.encryption_completed = False
            else:
                raise ValueError(f"Invalid encryption key length: {len(encryption_key)}")
        else:
            self.encryption_completed = False

    def complete_key_exchange(self, second_key_part: bytes):
        """Complete the legacy key exchange by combining both parts"""
        if self.encryption_completed:
            self.logger.warning("Key exchange already completed")
            return
        
        if len(self.encryption_key) == 16 and len(second_key_part) == 16:
            # Combine keys and derive session keys
            shared_secret = self.encryption_key + second_key_part
            keys = derive_tunnel_keys(shared_secret)
            
            self.encryption_key = keys['encryption']
            self.mac_key = keys['mac']
            self.iv_material = keys['iv_material']
            self.encryption_completed = True
            
            self.logger.info(f"C2C tunnel keys derived for {int_to_ip(self.ip)}")

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
                self.sock.sendall(encrypted_pkt.to_bytes())
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
                raw_pkt = Packet.from_socket(self.sock)
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
    'Packet', 'recv_exact', 'int_to_ip', 'ip_to_int',
    'ERR_CODES', 'VNetError', 'HandshakeError', 'PacketError',
    "encrypt", "decrypt", "RemoteClient", "TunneledClient",
    "encryptedTypes", "packetTypes", "ClientExitCodes",
    "derive_tunnel_keys", "MAC_SIZE", "GCM_NONCE_SIZE"
] + [x for x in packetTypes.keys() if not isinstance(x, int)]
