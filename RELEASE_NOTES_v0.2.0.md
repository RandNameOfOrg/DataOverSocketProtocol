# DoSP v0.2.0

## Highlights

### MPAK — Multi-Packet Aggregation (`0x1A`)
Bundle multiple packets into one compressed payload — fewer packets, better compression.

```python
from dosp import Packet, MPAK, MSG, S2C

# Bundle 50 messages into one wire packet
pkts = [Packet(MSG, f"msg {i}".encode()) for i in range(50)]
client.send_multi(pkts)

# Or create manually
mpak = Packet.multi(pkts)
client.send(mpak)

# Server unpacks transparently; client receive() drains sub-packets
```

Savings with compression enabled: **~86-89%** on repeated/structured payloads (cross-packet zlib redundancy).

### Runtime Compression
`ServerConfig(allow_compression=True, compression_level=6)` enables zlib at runtime — no source edits needed. Client auto-detects and enables compression when the server advertises it.

```python
from dosp.server import ServerConfig

cfg = ServerConfig(
    allow_compression=True,
    compression_level=9,
)
```

### Admin System
- Broadcast (`BCST 0x16`) — admin sends MSG to all connected clients
- Admin CLI: `python -m dosp.admin_cli --login admin changeme`
- Single-command exec: `python -m dosp.admin_cli --exec "clients"`
- Token auth via `AUTH (0x17)` packet
- Client identity hashing (`CLIENT_INFO 0x19`)
- Ban/whitelist by client hash
- Per-client & server packet counters

### New ServerConfig Fields
| Field | Default | Description |
|---|---|---|
| `allow_compression` | `False` | Enable zlib compression |
| `compression_level` | `6` | zlib level 1-9 |
| `max_packet_size` | `0` | Reject oversized packets (0=unlimited) |
| `socket_timeout` | `30.0` | Per-client socket timeout (0=blocking) |
| `max_clients` | `256` | Connection limit |
| `admin_tokens` | `[]` | Auto-generated if empty |
| `admin_token_file` | `None` | Write auto-generated token to file |
| `banned_hashes` | `[]` | Blocked client hashes |
| `whitelist_hashes` | `[]` | Allowed client hashes |
| `hash_whitelist_enabled` | `False` | Lock to whitelist only |

### Other Changes
- Pydantic removed — `ServerConfig` uses stdlib dataclasses
- `--gen-config` now generates a single `dosp.yaml` (richer content, no .env.example)
- WebSocket transport support (`dosp/ws_transport.py`, `examples/server_wss.py`)
- `TunneledClient` with DH (X25519) C2C encryption — server cannot decrypt

## Upgrade Notes
- `ServerConfig` no longer accepts pydantic validators — plain dataclass fields only
- Compression is runtime-switchable via `dosp.protocol.set_compression()` — module-level `ENABLE_COMPRESSION` flag is still readable but changes at runtime
- `--gen-config` no longer writes `.env.example` — only `dosp.yaml`
