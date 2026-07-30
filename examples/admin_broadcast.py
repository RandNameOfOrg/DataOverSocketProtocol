"""Example: Start server and admin client that broadcasts to all connected clients.
Usage:
  python examples/admin_broadcast.py [--token <token>]
"""
import argparse
import threading
import time

from dosp import DoSP, ServerConfig, Client, generate_admin_token, int_to_ip


def main():
    parser = argparse.ArgumentParser(description="DoSP admin broadcast example")
    parser.add_argument("--token", default=None, help="Admin token (auto-generated if not set)")
    parser.add_argument("--port", type=int, default=7744, help="Server port")
    args = parser.parse_args()

    token = args.token or generate_admin_token("admin", "changeme")
    print(f"Admin token: {token}")

    config = ServerConfig(
        host="127.0.0.1",
        port=args.port,
        admin_tokens=[token],
        allow_local=False,
    )
    server = DoSP(config)
    server.start(detach=True)

    time.sleep(0.2)

    admin = Client(host="127.0.0.1", port=args.port)
    print(f"Admin vIP: {int_to_ip(admin.vip_int)}")

    if not admin.authenticate_admin(token):
        print("Auth failed!")
        admin.close()
        server.stop()
        return

    print("Authenticated as admin. Broadcasting...")
    resp = admin.broadcast("Hello, all clients! This is your admin.")
    print(f"Broadcast response: {resp}")

    resp = admin.admin_command("clients")
    print(f"Clients: {resp}")

    resp = admin.admin_command("kick 7.10.0.2")
    print(f"Kick response: {resp}")

    admin.close()
    server.stop()


if __name__ == "__main__":
    main()
