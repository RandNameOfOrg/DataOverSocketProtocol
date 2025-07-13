from vnet.server import DoSP
from vnet.protocol import *

class CoolServer(DoSP):
    def handle_packet(self, pkt: Packet, sock, ip):
        if pkt.type == S2C:
            print(f"[ROUTE][{int_to_ip(ip)} -> {int_to_ip(pkt.dst_ip)}] data:", pkt)
            super().handle_packet(pkt, sock, ip)
        elif pkt.type == RQIP:
            print("[RQIP] data:", pkt, "from", int_to_ip(ip))
        elif pkt.type == MSG:
            super().handle_packet(pkt, sock, ip)
        else:
            print("[UNKNOWN] data:", pkt, "from", int_to_ip(ip))

if __name__ == "__main__":
    server = CoolServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
