import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dosp.client import Client
from dosp.protocol import *
import threading

running = True

def handler(client: Client):
    while True:
        pkt = client.receive()
        print(pkt, "From while True")
        if pkt.src_ip is None:
            print("No src_ip")
            continue
        if pkt is None or pkt.type == EXIT:
            break
        if pkt.type == S2C:
            print("Received S2C packet from", int_to_ip(pkt.src_ip))
            client.send(Packet(S2C, b"Hello client", dst_ip=pkt.src_ip), on_error="ignore")


with Client(host="10.0.0.15", vip="7.10.0.1") as client:
    print("vIP:", int_to_ip(client.vip_int))
    client.send(Packet(MSG, b"Hello server"))
    thread = threading.Thread(target=handler, args=(client,), daemon=True)
    thread.start()
    thread.join()