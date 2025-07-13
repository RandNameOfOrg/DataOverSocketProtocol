from vnet.client import Client
from vnet.protocol import *

with Client(vip="7.10.0.1") as client:
    print("vIP:", int_to_ip(client.vip_int))
    client.send(Packet(MSG, b"Hello server"))
    client.do_c2c_handshake(c2c_vip=client.vip_int)
    while True:
        pkt = client.receive()
        print(pkt)
        if pkt is None or pkt.type == EXIT:
            break