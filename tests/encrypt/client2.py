import os
import threading
import time

from vnet.client import Client
from vnet.protocol import Packet, S2C, MSG, int_to_ip

HOST = os.getenv("VNET_HOST", "127.0.0.1")
PORT = int(os.getenv("VNET_PORT", "7744"))

# Client2 acts as a responder: it accepts tunnel handshakes and echoes
# back any encrypted S2C messages it receives from peers.

def recv_loop(client: Client):
    while True:
        pkt = client.receive(on_error="ignore")
        if pkt is None:
            time.sleep(0.05)
            continue
        if pkt.type == S2C:
            print(f"[client2] <- S2C from {int_to_ip(pkt.src_ip)}: {pkt.payload!r}")
            # Echo back through the encrypted tunnel
            try:
                client.send(Packet(S2C, b"echo: " + pkt.payload, dst_ip=pkt.src_ip))
                print(f"[client2] -> echoed back to {int_to_ip(pkt.src_ip)}")
            except Exception as e:
                print("[client2] failed to echo:", e)
        elif pkt.type == MSG:
            print(f"[client2] <- MSG: {pkt.payload!r}")


def main():
    with Client(host=f"{HOST}:{PORT}") as client:
        print("[client2] vIP:", int_to_ip(client.vip_int))
        client.send(Packet(MSG, b"client2 online"), on_error="ignore")

        t = threading.Thread(target=recv_loop, args=(client,), daemon=True)
        t.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
