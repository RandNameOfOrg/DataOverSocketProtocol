from vnet.protocol import *
import socket

s = socket.create_connection(('127.0.0.1', 5050))

# Получить свой виртуальный IP (type 0x20)
pkt = Packet.from_socket(s)
my_ip = int_to_ip(int.from_bytes(pkt.payload, 'big'))
print("My IP:", my_ip)

# Request virtual IP (type 0x07)
pkt = Packet(RQIP, bytes(ip_to_int("7.10.0.5")))
s.sendall(pkt.to_bytes())

pkt = Packet.from_socket(s)
print(pkt)
my_ip = int_to_ip(int.from_bytes(pkt.payload, 'big'))
print("My IP:", my_ip)

# Отправить обычное сообщение (type 0x01)
msg = Packet(MSG, b"Hello server")
s.sendall(msg.to_bytes())

# Отправить сообщение другому клиенту (type 0x03)
dst_ip = ip_to_int("7.10.0.2")
to_peer = Packet(0x03, b"Hello peer", dst_ip)
s.sendall(to_peer.to_bytes())

# Получение ответов
while True:
    pkt = Packet.from_socket(s)
    if pkt is None:
        break
    print(f"[{hex(pkt.type)}] {pkt.payload.decode()}")

