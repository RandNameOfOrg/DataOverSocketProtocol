import logging
import socket
import struct

from abc import ABC
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
#-----  Server Answers  -----#
R4C  = 0x0F  # Received from client
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
    RQIP: "RQIP", R4C: "R4C",
    SA: "SA",
    EXIT: "EXIT", ERR: "ERR",
    AIP: "AIP",   HSK: "HSK",
    HC2C: "HC2C"
}
_ = {}
for k, v in packetTypes.items():
    _[v] = k
packetTypes = packetTypes | _

encryptedTypes = {
    S2C, R4C
}

class ERR_CODES:
    FNF   = 0x01
    FF    = 0x02
    S2CF  = 0x03
    RQIPF = 0x04
    SDF   = 0x05
    GCLF  = 0x06
    AIPF  = 0x07
    HSKF  = 0x08
    UKNP  = 0x09

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


def recv_exact(sock, size: int) -> bytes | None:
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

    # Генерируем случайный nonce (12 байт)
    nonce = get_random_bytes(GCM_NONCE_SIZE)

    # Шифруем
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Формат: nonce (12) + ciphertext + tag (16)
    return nonce + ciphertext + tag

def decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypts data using AES-GCM.
    :return: data (bytes)"""
    if len(data) < GCM_NONCE_SIZE + 16:
        raise ValueError("Invalid ciphertext (too short)")

    # Разделяем nonce, ciphertext и tag
    nonce = data[:GCM_NONCE_SIZE]
    ciphertext = data[GCM_NONCE_SIZE:-16]
    tag = data[-16:]

    # Дешифруем
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

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
                raise VNetException("failed to receive packet header")
            return None

        type_, length = struct.unpack(">BI", header)
        data = recv_exact(sock, length)
        if data is None:
            if raise_on_error:
                raise VNetException("failed to receive packet data")
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
                    raise VNetException("invalid S2C packet (missing dst_ip)")
                return None
            dst_ip = struct.unpack(">I", data[:4])[0]
            payload = data[4:]
            return Packet(type_, payload, dst_ip=dst_ip, src_ip=src_ip)

        return Packet(type_, data, src_ip=src_ip)

    def __str__(self) -> str:
        base = f"type={packetTypes[self.type]}, payload={self.payload}"
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
        if self.encryption_key is not None:
            self.encryption_completed = len(self.encryption_key) == 32
        else:
            self.encryption_completed = False

    def send(self, pkt: Packet) -> None:
        if self.sock is not None:
            self.sock.sendall(pkt.to_bytes())

    def recv(self) -> Packet | None:
        return Packet.from_socket(self.sock)

class TunneledClient(IClient):
    def __init__(self, ip: int, logger: logging.Logger, encryption_key, sock: socket.socket | None = None) -> None:
        self.sock = sock
        self.ip = ip
        self.logger = logger

        self.encryption_key = encryption_key
        self.encryption_completed = len(self.encryption_key) == 32

    def send(self, pkt: Packet) -> None:
        if self.encryption_completed and self.sock is not None:
            pkt.encryption_key = self.encryption_key
            pkt.src_ip = self.ip
            self.sock.sendall(pkt.to_bytes())
        else:
            self.logger.warning("TunneledClient.send called before encryption completed")

    def recv(self) -> Packet | None:
        if self.encryption_completed and self.sock is not None:
            return Packet.from_socket(self.sock, encryption_key=self.encryption_key)
        else:
            return None

    def decrypt(self, pkt: Packet) -> Packet:
        if self.encryption_completed:
            return Packet(pkt.type, pkt.payload, pkt.dst_ip, pkt.src_ip, self.encryption_key)
        else:
            return pkt

class VNetException(Exception): pass

class PacketError(VNetException):
    def __init__(self, msg: str) -> None:
        super().__init__("Packet error: " + msg)

class HandshakeError(VNetException):
    def __init__(self, msg: str) -> None:
        super().__init__("Handshake error: " + msg)


__all__ = [
    'Packet', 'recv_exact', 'int_to_ip', 'ip_to_int',
    'ERR_CODES', 'VNetException', 'HandshakeError', 'PacketError',
    "encrypt", "decrypt", "RemoteClient", "TunneledClient",
    "encryptedTypes", "packetTypes"
] + [x for x in packetTypes.keys() if not isinstance(x, int)]
