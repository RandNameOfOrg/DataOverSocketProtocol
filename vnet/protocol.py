import logging
import socket
import struct

from abc import ABC
from enum import Enum

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
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

encryptedTypes = {
    S2C
}

class ClientExitCodes(Enum):
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

# packetTypes = {
#     "MSG": MSG,   "PING": PING,
#     "S2C": S2C,   "GCL":  GCL,
#     "FN": FN,     "SD": SD,
#     "RQIP": RQIP, "R4C": R4C,
#     "SA": SA,
#     "EXIT": EXIT, "ERR": ERR,
#     "AIP": AIP,   "HSK": HSK,
#     "HC2C": HC2C
# }
# endregion

GCM_NONCE_SIZE = 12 # For encryption

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
            total_payload = dst_bytes + self.payload
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

        if encryption_key and type_ in encryptedTypes:
            try:
                data = decrypt(data, encryption_key)
            except ValueError as e:
                if raise_on_error:
                    raise PacketError(f"Decryption failed: {e}")
                return None

        if type_ == S2C:
            if len(data) < 4:
                if raise_on_error:
                    raise VNetError("invalid S2C packet (missing dst_ip)")
                return None
            dst_ip = struct.unpack(">I", data[:4])[0]
            payload = data[4:]
            return Packet(type_, payload, dst_ip=dst_ip, src_ip=src_ip)

        return Packet(type_, data, src_ip=src_ip)

    def __str__(self) -> str:
        base = f"type={packetTypes[self.type]}, payload={self.payload}, encrypted={self.encryption_key is not None}"
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
    def __init__(self, ip: int, logger: logging.Logger, encryption_key, sock: socket.socket | None = None):
        self.sock = sock
        self.ip = ip
        self.logger = logger
        self.encryption_key = encryption_key
        self.encryption_completed = len(self.encryption_key) == 32
        self.message_queue = []  # For local communication

    def send(self, pkt: Packet) -> None:
        if not self.encryption_completed:
            self.logger.warning("TunneledClient.send called before encryption completed")
            return

        try:
            encrypted_payload = encrypt(pkt.payload, self.encryption_key)
            encrypted_pkt = Packet(pkt.type, encrypted_payload, pkt.dst_ip, pkt.src_ip)

            if self.sock is not None:
                self.sock.sendall(encrypted_pkt.to_bytes())
            else:
                # For local communication
                self.message_queue.append(encrypted_pkt)
        except Exception as e:
            self.logger.error(f"Failed to encrypt and send packet: {e}")

    def recv(self) -> Packet | None:
        if not self.encryption_completed:
            self.logger.warning("TunneledClient.recv called before encryption completed")
            return None

        try:
            if self.sock is not None:
                raw_pkt = Packet.from_socket(self.sock)
                if raw_pkt is None:
                    return None
                decrypted_payload = decrypt(raw_pkt.payload, self.encryption_key)
                return Packet(raw_pkt.type, decrypted_payload, raw_pkt.dst_ip, raw_pkt.src_ip)
            else:
                # For local communication
                if not self.message_queue:
                    return None
                raw_pkt = self.message_queue.pop(0)
                decrypted_payload = decrypt(raw_pkt.payload, self.encryption_key)
                return Packet(raw_pkt.type, decrypted_payload, raw_pkt.dst_ip, raw_pkt.src_ip)
        except Exception as e:
            self.logger.error(f"Failed to receive and decrypt packet: {e}")
            return None

    def decrypt(self, pkt: Packet) -> Packet:
        if not self.encryption_completed:
            return pkt

        try:
            decrypted_payload = decrypt(pkt.payload, self.encryption_key)
            return Packet(pkt.type, decrypted_payload, pkt.dst_ip, pkt.src_ip)
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            return pkt

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
    "encryptedTypes", "packetTypes", "ClientExitCodes"
] + [x for x in packetTypes.keys() if not isinstance(x, int)]
