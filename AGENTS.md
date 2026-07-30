# DoSP — Agent Guide

## Project
- **Package**: `dosp` (PyPI: `DoSP`), Python >=3.10, setuptools build
- **Install dev**: `pip install -e .`
- **GUI deps**: `pip install -r gui/requirements.txt` (requires `customtkinter`)

## Repo layout
```
dosp/          # import dosp
├── __init__.py    # re-exports: Client, Packet, MSG, ..., ip_to_int, int_to_ip, server.*
├── protocol.py    # Packet, enums (MSG=0x01..HC2C=0x15), encrypt/decrypt, TunneledClient
├── client.py      # Client, LocalClient
├── iptools.py     # ip_to_int / int_to_ip / ip_to_id
├── ws_transport.py # WebSocket transport adapter (wsproto + simple-websocket)
└── server/
    ├── __init__.py   # exports DoSP, RemoteServer, ServerConfig
    └── base.py       # DoSP class, ServerConfig
gui/dosp_client_gui.py   # CustomTkinter GUI
tests/asyncio/           # multi-client test harness (manual run, no framework)
tests/encrypt/           # manual C2C encryption test scripts
examples/                # reference scripts
```

## Key commands
- **Start server**: `python examples/server.py`
- **Start WSS server**: `python examples/server_wss.py` (needs `pip install simple-websocket`)
- **Start interactive client**: `python examples/interactive_messager.py`
- **Admin CLI (interactive)**: `python -m dosp.admin_cli --host 127.0.0.1 --port 7744 --token <token>`
- **Admin CLI with login**: `python -m dosp.admin_cli --login admin changeme`
- **Admin single command**: `python -m dosp.admin_cli --token <token> --exec "clients"`
- **Broadcast example**: `python examples/admin_broadcast.py`
- **Run multi-client test**: `python -m tests.asyncio.multi_client_test --mode single --clients 4 --handshake`
- **Run cross-server test**: `python -m tests.asyncio.multi_client_test --mode cross --port 7744`
- **No linter / type checker / CI / test framework configured**

## Architecture
- **Server** (`DoSP`): accepts TCP, assigns vIPs, routes S2C, federates peers. `start(detach=False)` blocks (default); pass `detach=True` for thread. `stop()` sends EXIT to all clients.
- **Client** (`Client`): synchronous, blocking send/receive. Context manager (`with Client(...)`) calls `sock.close()` but does **not** send EXIT. Must use `client.close()` for graceful disconnect.
- **C2C encryption**: DH (X25519) via S2C routed through server — server cannot decrypt. Done via `client.do_c2c_handshake(target_vip)`.
- **WSS/WS transport**: Optional WebSocket transport via `simple-websocket` (client) + `wsproto` (server). Enable with `ServerConfig(wss_enabled=True)` or client `Client(..., use_ws=True)`. Install deps: `pip install simple-websocket`.

## Packet wire format
```
[1B TYPE] [4B LENGTH (big-endian)] [PAYLOAD]
```
- S2C (0x03) payload is: `[4B dst_ip][4B src_ip][compressed user data]`
- All other types payload is: `[compressed user data]`
- `struct.pack(">BI", ...)` — 1 byte type, 4 bytes length. README says "2B TYPE" but code says 1 byte; code is truth.
- Compression: runtime-toggleable via `protocol.set_compression(enabled, level)`. `ServerConfig.allow_compression` + `compression_level` control it. Client auto-enables compression if server advertises it. Packet methods use module-level `zlib` reference that gets swapped at runtime.

## Admin & Client Identity
- **Client hash**: Auto-generated on `Client.__init__()` via `get_client_hash()` — uses MAC address + hostname + machine GUID (Windows) or `/etc/machine-id` (Linux). SHA256 hex digest. Cannot be set externally without modifying source code. Sent to server as `CLIENT_INFO (0x19)` packet right after handshake.
- **Admin auth**: Server checks `CLIENT_INFO` hash against `ServerConfig.banned_hashes` (or whitelist). Client sends admin token via `AUTH (0x17)` packet. Server marks `RemoteClient.is_admin = True`.
- **Admin tokens**: Generated via `generate_admin_token(username, password)` = `sha256(user:pass)`. If `ServerConfig.admin_tokens` is empty, server auto-generates a random hex token (logged to console). Can also write to a file via `admin_token_file` config.
- **ServerConfig** fields: `allow_compression`, `compression_level` (1-9), `max_packet_size` (0=unlimited), `socket_timeout` (0=blocking), `max_clients` (0=unlimited).
- **Admin commands**: `ADMIN (0x18)` packet. Server-side `_handle_admin_command()` dispatches: `clients`, `kick`, `ban`, `unban`, `whitelist`, `block`, `unblock`, `stats`, `broadcast`, `help`, `exit`.
- **Broadcast**: `BCST (0x16)` packet — admin-only. Server sends payload as `MSG (0x01)` to all connected clients. Returns `BCST` response to admin with recipient count.
- **Server counters**: `server_packets_received`, `server_packets_sent` on `DoSP`. Per-client: `packets_received`, `packets_sent` on `RemoteClient`.

## Quirks & gotchas
- `ServerConfig.ip_template` uses `{x}` (e.g. `"7.10.0.{x}"`) — normalized to `"x"` at init. Server gets `.1`, clients start at `.2`.
- `LocalClient` sends via `server.handle_packet()` and receives from `RemoteClient.message_queue` on the server side. Works only if `allow_local=True`.
- `dosp/__init__.py` does `from .protocol import *` — `__all__` in protocol.py controls what's exported. Useful constants (MSG, S2C, etc.) come from there.
- `from dosp import Client, Packet, MSG, ip_to_int` works directly.
- No `.github/workflows/` — CI not set up.
- `Band IP list` on `ServerConfig.banned_ip_list` blocks `0.0.0.0` and `127.0.0.1` by default.
