import os
import sys
import threading
import time

from dosp.client import Client
from dosp.protocol import Packet, S2C, MSG, int_to_ip, ip_to_int

HOST = os.getenv("VNET_HOST", "127.0.0.1")
PORT = int(os.getenv("VNET_PORT", "7744"))

# Usage: python tests/encrypt/client1.py <target_vip>
# Example: python tests/encrypt/client1.py 7.10.0.3

def recv_loop(client: Client):
    while True:
        pkt = client.receive(on_error="ignore")
        if pkt is None:
            time.sleep(0.05)
            continue
        # Print any decrypted S2C and MSG
        if pkt.type == S2C:
            print(f"[client1] <- S2C from {int_to_ip(pkt.src_ip)}: {pkt.payload!r}")
        elif pkt.type == MSG:
            print(f"[client1] <- MSG: {pkt.payload!r}")


def main():
    # if len(sys.argv) < 2:
    #     print("Usage: python tests/encrypt/client1.py <target_vip>")
    #     print("Hint: run client2 first and copy its vIP printed on start")
    #     sys.exit(1)
    # target_vip = sys.argv[1]
    target_vip = "7.10.0.2"
    target_ip_int = ip_to_int(target_vip)

    with Client(host=f"{HOST}:{PORT}") as client:
        print("[client1] vIP:", int_to_ip(client.vip_int))
        # Optional: greet server
        client.send(Packet(MSG, b"client1 online"), on_error="ignore")

        # Initiate C2C handshake and create encrypted tunnel
        print(f"[client1] starting tunnel handshake to {target_vip}...")
        client.do_c2c_handshake(target_ip_int)
        print(f"[client1] tunnel established with {target_vip}")

        # Start background receiver
        t = threading.Thread(target=recv_loop, args=(client,), daemon=True)
        t.start()

        # Send an encrypted message through the tunnel
        client.send(Packet(S2C, b"hello from client1 over encrypted tunnel", dst_ip=target_ip_int))
        print("[client1] -> sent encrypted S2C to", target_vip)

        # Keep the script alive for manual testing
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
