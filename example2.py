from vnet.client import Client
from vnet.protocol import *

with Client(vip="7.10.0.1") as client:
    print("vIP:", int_to_ip(client.vip_int))
    client.send(Packet(MSG, b"Hello server"))

    while True:
        pkt = client.receive()
        print(pkt)
        if pkt is None or pkt.type == EXIT:
            break
        if pkt.type == R4C:
            print("Received R4C packet from", int_to_ip(pkt.src_ip))
            client.send(Packet(R4C, b"Hello client", dst_ip=pkt.src_ip), on_error="ignore")