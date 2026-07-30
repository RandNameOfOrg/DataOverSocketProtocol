"""DoSP server with WSS (WebSocket Secure) support.

Usage:
    python examples/server_wss.py                        # TCP + WS (no TLS)
    python examples/server_wss.py --wss                  # TCP + WSS (self-signed cert)
    python examples/server_wss.py --wss-port 443         # Custom WSS port
    python examples/server_wss.py --wss-only             # WSS only (no TCP)
"""

import argparse
import logging

from dosp import DoSP, ServerConfig

logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser(description="DoSP Server with WSS")
parser.add_argument("--host", default="0.0.0.0")
parser.add_argument("--port", type=int, default=7744, help="TCP port")
parser.add_argument("--wss", action="store_true", help="Enable WebSocket (WSS if cert/key provided)")
parser.add_argument("--wss-port", type=int, default=7745, help="WebSocket port (default: 7745)")
parser.add_argument("--wss-only", action="store_true", help="Listen only on WebSocket, no TCP")
parser.add_argument("--cert", default=None, help="SSL cert file (PEM)")
parser.add_argument("--key", default=None, help="SSL key file (PEM)")
parser.add_argument("--ip-template", default="7.10.0.x")
args = parser.parse_args()

config = ServerConfig(
    host=args.host,
    port=args.port,
    ip_template=args.ip_template,
)

if args.wss or args.wss_only:
    config.wss_enabled = True
    config.wss_port = args.wss_port
    config.wss_certfile = args.cert
    config.wss_keyfile = args.key

if not args.wss_only:
    print(f"TCP server listening on {args.host}:{args.port}")
if args.wss:
    proto = "WSS" if args.cert else "WS"
    print(f"{proto} server listening on {args.host}:{args.wss_port}")

server = DoSP(config)
server.start()
