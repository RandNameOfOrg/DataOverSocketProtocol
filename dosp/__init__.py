from .iptools import ip_to_int, int_to_ip, ip_to_id
from .protocol import *
from .server import *
from .client import Client


def _main():
    import argparse
    import logging

    parser = argparse.ArgumentParser(description="Data over Socket Protocol")
    parser.add_argument("--serve", action="store_true", help="Start the DoSP server")
    parser.add_argument("--host", default="0.0.0.0", help="Server host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=7744, help="Server port (default: 7744)")
    parser.add_argument("--ip-template", default="7.10.0.x", help="Virtual IP template (default: 7.10.0.x)")
    parser.add_argument("--peers", nargs="*", metavar="HOST:PORT:TEMPLATE", help="Peer servers to connect to")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--detach", action="store_true", help="Run server in background thread")
    parser.add_argument("--client", action="store_true", help="Connect as a client and enter interactive mode")
    parser.add_argument("--vip", default=None, help="Request a specific virtual IP")

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    if args.serve:
        from .server.base import ServerConfig
        config = ServerConfig(
            host=args.host,
            port=args.port,
            ip_template=args.ip_template,
        )
        server = DoSP(config)
        if args.peers:
            for peer_str in args.peers:
                parts = peer_str.split(":")
                host = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 7744
                tmpl = parts[2] if len(parts) > 2 else None
                server.add_peer_server(host, port, tmpl)
        try:
            server.start(detach=args.detach)
            if args.detach:
                print(f"Server started on {args.host}:{args.port} (detached)")
        except KeyboardInterrupt:
            server.stop()
    elif args.client:
        host = args.host if args.host != "0.0.0.0" else "127.0.0.1"
        client = Client(host=host, port=args.port, vip=args.vip)
        print(f"Connected. Your vIP: {int_to_ip(client.vip_int)}")
        try:
            while True:
                msg = input("> ")
                if msg.strip().lower() in ("/exit", "/quit"):
                    break
                if msg.strip().lower().startswith("/send "):
                    parts = msg.split(maxsplit=2)
                    if len(parts) >= 3:
                        target = parts[1]
                        text = parts[2]
                        client.send(Packet(S2C, text.encode(), dst_ip=ip_to_int(target)))
                        print(f"Sent to {target}: {text}")
                    else:
                        print("Usage: /send <vip> <message>")
                else:
                    print("Commands: /send <vip> <message>, /exit")
        except KeyboardInterrupt:
            pass
        client.close()
    else:
        parser.print_help()


if __name__ == "__main__":
    _main()