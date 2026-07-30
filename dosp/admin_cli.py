"""DoSP Admin CLI - remote server administration tool.

Usage:
  python -m dosp.admin_cli --host 127.0.0.1 --port 7744 --token <token>
  python -m dosp.admin_cli --host 127.0.0.1 --port 7744 --login <username> <password>
  python -m dosp.admin_cli --host 127.0.0.1 --port 7744 --token <token> --exec "clients"

If no --token or --login is given, tries to read token from dosp_admin.token in CWD.
"""

import argparse
import logging
import os
import sys

from .client import Client
from .protocol import generate_admin_token, int_to_ip


def read_token_file(path: str = "dosp_admin.token") -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return None


def run_interactive(client: Client) -> None:
    print(f"Connected. Your vIP: {int_to_ip(client.vip_int)}")
    print("Type 'help' for available commands, 'exit' to quit.")
    try:
        while True:
            try:
                cmd = input("admin> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit", "/exit", "/quit"):
                break
            resp = client.admin_command(cmd)
            if resp is not None:
                print(resp)
            else:
                print("Error: no response from server (connection may be lost)")
                break
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()


def run_exec(client: Client, command: str) -> None:
    resp = client.admin_command(command)
    if resp is not None:
        print(resp)
    else:
        print("Error: no response from server")
        sys.exit(1)
    client.close()


def main():
    parser = argparse.ArgumentParser(description="DoSP Admin CLI")
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=7744, help="Server port (default: 7744)")
    parser.add_argument("--token", default=None, help="Admin token for authentication")
    parser.add_argument("--login", nargs=2, metavar=("USERNAME", "PASSWORD"),
                        help="Generate token from username and password")
    parser.add_argument("--exec", default=None, help="Execute a single command and exit")
    parser.add_argument("--token-file", default="dosp_admin.token",
                        help="Path to token file (default: dosp_admin.token)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    # Resolve token
    token = args.token
    if not token and args.login:
        token = generate_admin_token(args.login[0], args.login[1])
    if not token:
        token = read_token_file(args.token_file)
    if not token:
        print("Error: No admin token provided. Use --token, --login, or create dosp_admin.token")
        sys.exit(1)

    # Connect
    client = Client(host=args.host, port=args.port)
    if not client.authenticate_admin(token):
        print("Error: Admin authentication failed")
        client.close()
        sys.exit(1)

    if args.exec:
        run_exec(client, args.exec)
    else:
        run_interactive(client)


if __name__ == "__main__":
    main()
