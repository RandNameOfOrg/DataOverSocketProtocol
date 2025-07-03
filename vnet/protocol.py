import struct
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
SA   = 0x10  # Server answer
EXIT = 0x11  # Exit
ERR  = 0x12  # Error
AIP  = 0x20  # Assign IP

packetTypes = {
    "MSG": MSG,   "PING": PING,
    "S2C": S2C,   "GCL":  GCL,
    "FN": FN,     "SD": SD,
    "RQIP": RQIP, "SA": SA,
    "EXIT": EXIT, "ERR": ERR,
    "AIP": AIP
}
# endregion

__all__ = ['Packet', 'recv_exact', 'int_to_ip', 'ip_to_int', *packetTypes.keys()]

class Packet:
    def __init__(self, type_: int, payload: bytes, dst_ip: int = None):
        globals().update(packetTypes)
        self.type    = type_
        self.payload = payload
        self.dst_ip  = dst_ip

    def to_bytes(self) -> bytes:
        if self.type == S2C:
            if self.dst_ip is None:
                raise ValueError(f"dst_ip required for type {S2C}")
            dst_bytes = struct.pack(">I", self.dst_ip)
            total_payload = dst_bytes + self.payload
            return struct.pack(">BI", self.type, len(total_payload)) + total_payload
        else:
            return struct.pack(">BI", self.type, len(self.payload)) + self.payload

    @staticmethod
    def from_socket(sock) -> 'Packet | None':
        header = recv_exact(sock, 5)
        if not header:
            return None
        type_, length = struct.unpack(">BI", header)
        data = recv_exact(sock, length)
        if data is None:
            return None
        if type_ == S2C:
            if len(data) < 4:
                return None
            dst_ip = struct.unpack(">I", data[:4])[0]
            payload = data[4:]
            return Packet(type_, payload, dst_ip=dst_ip)
        return Packet(type_, data)

def recv_exact(sock, size: int) -> bytes | None:
    buf = b''
    while len(buf) < size:
        part = sock.recv(size - len(buf))
        if not part:
            return None
        buf += part
    return buf
