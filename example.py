from vnet.client import Client
from vnet.protocol import *

with Client(vip="7.10.0.1") as client:
    print("vIP:", int_to_ip(client.vip_int))
    client.send(Packet(MSG, b"Hello server"))
    client.do_c2c_handshake(c2c_vip=client.vip_int - 1)

    client.send(Packet(
        S2C,
        b"Hello client",
        dst_ip=client.vip_int + 1 # send to this client for testing
    ), on_error="ignore")

    while True:
        pkt = client.receive()
        print(pkt, "BRUH")
        if pkt is None or pkt.type == EXIT:
            break
