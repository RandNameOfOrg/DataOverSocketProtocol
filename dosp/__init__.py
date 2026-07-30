from .iptools import ip_to_int, int_to_ip, ip_to_id
from .protocol import *
from .server import *
from .client import Client
from .admin_cli import main as admin_cli_main
from .ws_transport import WebSocketTransport, WSServerConfig, ws_available


def _load_config(path: str | None = None) -> dict:
    """Load config from YAML file and .env file. Returns merged dict."""
    import os

    config: dict = {}

    yaml_path = None
    if path:
        yaml_path = path
    else:
        for candidate in ("dosp.yaml", "dosp.yml", "config.yaml", "config.yml"):
            if os.path.isfile(candidate):
                yaml_path = candidate
                break

    if yaml_path:
        try:
            import yaml as _yaml
            with open(yaml_path, encoding="utf-8") as f:
                data = _yaml.safe_load(f)
            if isinstance(data, dict):
                config.update(data)
        except ImportError:
            print("yaml module not available; install with: pip install pyyaml")
        except Exception as e:
            print(f"Failed to load {yaml_path}: {e}")

    env_path = os.environ.get("DOSP_ENV_FILE") or ".env"
    if os.path.isfile(env_path):
        try:
            with open(env_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    val = val.strip().strip("\"'")
                    os.environ.setdefault(key, val)
        except Exception as e:
            print(f"Failed to load {env_path}: {e}")

    env_map = {
        "serve": ("DOSP_SERVE", lambda v: v.lower() in ("1", "true", "yes")),
        "host": ("DOSP_HOST", str),
        "port": ("DOSP_PORT", int),
        "ip_template": ("DOSP_IP_TEMPLATE", str),
        "peers": ("DOSP_PEERS", lambda v: [p.strip() for p in v.split(",") if p.strip()]),
        "debug": ("DOSP_DEBUG", lambda v: v.lower() in ("1", "true", "yes")),
        "detach": ("DOSP_DETACH", lambda v: v.lower() in ("1", "true", "yes")),
        "vip": ("DOSP_VIP", str),
    }
    for cfg_key, (env_key, cast) in env_map.items():
        val = os.environ.get(env_key)
        if val is not None:
            try:
                config[cfg_key] = cast(val)
            except Exception:
                pass

    if config.get("ip_template") and "{x}" in config["ip_template"]:
        config["ip_template"] = config["ip_template"].replace("{x}", "x")

    return config


def _merge_config(args, config: dict, key: str, arg_default=None):
    """CLI arg wins over config file for non-None/non-default values."""
    cli_val = getattr(args, key, None)
    cfg_val = config.get(key)
    if key in ("serve", "client", "debug", "detach"):
        if cli_val:
            return cli_val
        if cfg_val:
            return cfg_val
        return arg_default if arg_default is not None else False
    if key in ("host", "port", "ip_template", "vip"):
        if cli_val is not None and cli_val != arg_default:
            return cli_val
        if cfg_val is not None:
            return cfg_val
        return arg_default
    if key == "peers":
        if cli_val is not None and cli_val != arg_default:
            return cli_val
        if cfg_val is not None:
            return cfg_val
        return arg_default
    return cli_val if cli_val is not None else cfg_val


def _gen_config():
    """Write default dosp.yaml config file."""
    import os
    content = """# DoSP server configuration
serve: false            # Start the server on launch
host: 0.0.0.0           # Bind address
port: 7744              # Server port
ip_template: 7.10.0.x   # Virtual IP template
debug: false            # Enable debug logging
detach: false           # Run server in background thread

# Compression
allow_compression: false
compression_level: 6

# Limits
max_clients: 256
socket_timeout: 30.0    # seconds, 0 for blocking
# max_packet_size: 65536  # bytes, 0 for unlimited

# Admin
# admin_tokens:
#   - <sha256-hex-token>
# admin_token_file: admin.token
# banned_hashes:
#   - <sha256-hex>
# whitelist_hashes:
#   - <sha256-hex>
# hash_whitelist_enabled: false

# Peers (host:port:template)
# peers:
#   - 10.0.0.50:7744:7.10.0.x
#   - 10.0.0.51:7744:66.11.5.x

# WebSocket (requires simple-websocket)
# wss_enabled: false
# wss_port: 7745
# wss_certfile: path/to/cert.pem
# wss_keyfile: path/to/key.pem
"""
    fname = "dosp.yaml"
    if os.path.isfile(fname):
        print(f"{fname} already exists, skipping")
    else:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(content.lstrip())
        print(f"Created {fname}")


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
    parser.add_argument("--token", default=None, help="Admin token (for --admin mode)")
    parser.add_argument("--client", action="store_true", help="Connect as a client and enter interactive mode")
    parser.add_argument("--admin", action="store_true", help="Connect as admin (opens admin CLI)")
    parser.add_argument("--admin-exec", default=None, help="Execute admin command and exit")
    parser.add_argument("--vip", default=None, help="Request a specific virtual IP")
    parser.add_argument("--config", default=None, help="Path to YAML config file")
    parser.add_argument("--gen-config", action="store_true", help="Generate default dosp.yaml config file")

    args = parser.parse_args()

    if args.gen_config:
        _gen_config()
        return

    cfg = _load_config(args.config)

    serve = _merge_config(args, cfg, "serve")
    host = _merge_config(args, cfg, "host", "0.0.0.0")
    port = _merge_config(args, cfg, "port", 7744)
    ip_template = _merge_config(args, cfg, "ip_template", "7.10.0.x")
    peers = _merge_config(args, cfg, "peers")
    debug = _merge_config(args, cfg, "debug")
    detach = _merge_config(args, cfg, "detach")
    client_mode = _merge_config(args, cfg, "client")
    vip = _merge_config(args, cfg, "vip")

    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)

    if serve:
        from .server.base import ServerConfig
        srv_cfg = ServerConfig(
            host=host,
            port=port,
            ip_template=ip_template,
        )
        server = DoSP(srv_cfg)
        if peers:
            for peer_str in peers:
                parts = peer_str.split(":")
                phost = parts[0]
                pport = int(parts[1]) if len(parts) > 1 else 7744
                ptmpl = parts[2] if len(parts) > 2 else None
                server.add_peer_server(phost, pport, ptmpl)
        try:
            server.start(detach=detach)
            if detach:
                print(f"Server started on {host}:{port} (detached)")
        except KeyboardInterrupt:
            server.stop()
    elif client_mode:
        chost = host if host != "0.0.0.0" else "127.0.0.1"
        cli = Client(host=chost, port=port, vip=vip)
        print(f"Connected. Your vIP: {int_to_ip(cli.vip_int)}")
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
                        cli.send(Packet(S2C, text.encode(), dst_ip=ip_to_int(target)))
                        print(f"Sent to {target}: {text}")
                    else:
                        print("Usage: /send <vip> <message>")
                else:
                    print("Commands: /send <vip> <message>, /exit")
        except KeyboardInterrupt:
            pass
        cli.close()
    elif args.admin or args.admin_exec:
        from .admin_cli import run_interactive, run_exec
        chost = host if host != "0.0.0.0" else "127.0.0.1"
        token = args.token or os.environ.get("DOSP_ADMIN_TOKEN")
        if args.admin_exec and not token:
            # try reading token file
            from .admin_cli import read_token_file
            token = read_token_file()
        if not token:
            print("Error: Admin token required. Set DOSP_ADMIN_TOKEN or pass --token")
            return
        cli = Client(host=chost, port=port, vip=vip)
        if not cli.authenticate_admin(token):
            print("Error: Admin authentication failed")
            cli.close()
            return
        if args.admin_exec:
            run_exec(cli, args.admin_exec)
        else:
            run_interactive(cli)
    else:
        parser.print_help()


if __name__ == "__main__":
    _main()