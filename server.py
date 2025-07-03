from vnet.server import DoSP
from vnet.protocol import *

class CoolServer(DoSP):
    def handle_packet(self, pkt, sock, ip):
        if pkt.type == S2C:
            print(f"[ROUTE][{int_to_ip(ip)} -> {int_to_ip(pkt.dst_ip)}] data:", pkt)
            super().handle_packet(pkt, sock, ip)
        else:
            super().handle_packet(pkt, sock, ip)

if __name__ == "__main__":
    CoolServer(port=5050).start()
