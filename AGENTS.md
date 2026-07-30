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
└── server/
    ├── __init__.py   # exports DoSP, RemoteServer
    └── base.py       # DoSP class, ServerConfig (pydantic)
gui/dosp_client_gui.py   # CustomTkinter GUI
tests/asyncio/           # multi-client test harness (manual run, no framework)
tests/encrypt/           # manual C2C encryption test scripts
examples/                # reference scripts
```

## Key commands
- **Start server**: `python examples/server.py`
- **Start interactive client**: `python examples/interactive_messager.py`
- **Run multi-client test**: `python -m tests.asyncio.multi_client_test --mode single --clients 4 --handshake`
- **Run cross-server test**: `python -m tests.asyncio.multi_client_test --mode cross --port 7744`
- **No linter / type checker / CI / test framework configured**

## Architecture
- **Server** (`DoSP`): accepts TCP, assigns vIPs, routes S2C, federates peers. `start(detach=False)` blocks (default); pass `detach=True` for thread. `stop()` sends EXIT to all clients.
- **Client** (`Client`): synchronous, blocking send/receive. Context manager (`with Client(...)`) calls `sock.close()` but does **not** send EXIT. Must use `client.close()` for graceful disconnect.
- **C2C encryption**: DH (X25519) via S2C routed through server — server cannot decrypt. Done via `client.do_c2c_handshake(target_vip)`.

## Packet wire format
```
[1B TYPE] [4B LENGTH (big-endian)] [PAYLOAD]
```
- S2C (0x03) payload is: `[4B dst_ip][4B src_ip][compressed user data]`
- All other types payload is: `[compressed user data]`
- `struct.pack(">BI", ...)` — 1 byte type, 4 bytes length. README says "2B TYPE" but code says 1 byte; code is truth.
- Compression: module-level `ENABLE_COMPRESSION = False` in `protocol.py`. When off, zlib is a no-op pass-through. Also configurable per-server via `ServerConfig.allow_compression`.

## Quirks & gotchas
- `ServerConfig.ip_template` uses `{x}` (e.g. `"7.10.0.{x}"`) — normalized to `"x"` at init. Server gets `.1`, clients start at `.2`.
- `LocalClient` sends via `server.handle_packet()` and receives from `RemoteClient.message_queue` on the server side. Works only if `allow_local=True`.
- `dosp/__init__.py` does `from .protocol import *` — `__all__` in protocol.py controls what's exported. Useful constants (MSG, S2C, etc.) come from there.
- `from dosp import Client, Packet, MSG, ip_to_int` works directly.
- No `.github/workflows/` — CI not set up.
- `Band IP list` on `ServerConfig.banned_ip_list` blocks `0.0.0.0` and `127.0.0.1` by default.
