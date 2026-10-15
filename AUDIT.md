# DoSP Code Audit — Bugs & Improvements

> Status legend: ✅ FIXED — resolved in the working tree; 🔶 REMAINS — still present.

## CRITICAL

### 1. `self.ip_template` references non-existent attribute → AttributeError
**File:** `dosp/server/base.py`
**Status:** ✅ FIXED — `DoSP.__init__` now sets `self.ip_template = self.config.ip_template`; `_build_advertisement_payload()` builds fine.

---

## HIGH

### 2. RQIP handler calls `on_disconnect(new_ip)` with wrong IP
**File:** `dosp/server/base.py` (RQIP handler)
**Status:** ✅ FIXED — the `on_disconnect` call was removed entirely. Old-IP cleanup happens via `clients.pop` + `assigned_ids.discard(old_ip_num)`; `RemoteClient.ip` is updated to the new IP.

### 3. `LocalClient.__init__` creates wrong RQIP payload with `bytes()`
**File:** `dosp/client.py`
**Status:** ✅ FIXED — uses `ip_to_int(vip).to_bytes(4, 'big')` for the RQIP payload.

### 4. `authenticate_admin()` / `broadcast()` / `admin_command()` race with receive loop
**File:** `dosp/client.py`
**Status:** ✅ FIXED — responses are routed through `_response_queues` (per-packet-type `Queue`), dispatched from the receive loop. A `_receive_response()` helper waits on the queue and falls back to a direct socket read when no receive loop is running.

### 5. Global `zlib` compression is not thread-safe
**File:** `dosp/protocol.py`
**Status:** ✅ FIXED — compression is now **per-connection** via `CompressionState`. Each `Client` and `DoSP` owns its own instance (`client.compression`, `server.compression`), passed to `Packet.to_bytes(compression=...)` / `Packet.from_socket(..., compression=...)`. `set_compression()` remains as a module-global default for backward compat. Peer-to-peer traffic is always uncompressed (`peer_compression`), so no negotiation is needed on peer links.

---

## MEDIUM

### 6. `RemoteClient.ip` stale after IP reassignment in RQIP handler
**File:** `dosp/server/base.py`
**Status:** ✅ FIXED — `client_obj.ip = new_ip` is set after reassignment.

### 7. `DoSP.running` is a class-level attribute
**File:** `dosp/server/base.py`
**Status:** ✅ FIXED — removed the class attribute; `self.running = True` is now set per-instance in `__init__`.

### 8. `stop()` does not notify remaining clients about disconnected peers
**File:** `dosp/server/base.py`
**Status:** ✅ FIXED — `stop()` now calls `on_disconnect(ip)` for every connected client before sending EXIT, so remaining clients receive UNREACHABLE notifications and clean up stale C2C tunnels.

### 9. `assigned_ids` incorrectly compares IP integers to `ip_num` values
**File:** `dosp/server/base.py`, `dosp/client.py`
**Status:** ✅ FIXED — both the RQIP handler and `LocalClient.close()` compute the template `x` position and use `ip_num` (octet at the `x` slot) for `add`/`discard`.

---

## LOW

### 9. `ip_to_id` crashes on invalid int input
**File:** `dosp/iptools.py`
**Status:** ✅ FIXED — `int_to_ip()` result is checked for `None` before `.split(".")`.

### 10. `Packet.unpack()` confusing error on non-MPAK type
**File:** `dosp/protocol.py`
**Status:** ✅ FIXED — error now includes the actual packet type.

### 11. `examples/interactive_messager.py:190+` — inconsistent indentation
**File:** `examples/interactive_messager.py`
**Status:** ✅ FIXED — `simple_interactive_client()` re-indented to 4 spaces; dead commented code removed.

---

## IMPROVEMENTS (not bugs)

Applied in the working tree:
- Per-client/per-server compression state instead of global `set_compression` (see HIGH #5).
- `Client.__exit__` now calls `close()` (sends EXIT) instead of just closing the socket.
- `_short_s2c` threshold/window/cooldown are configurable via `Client(...)` constructor kwargs.
- `Packet.__str__` now shows `src_ip` too.
- `handle_client` type hint accepts `socket.socket | WebSocketTransport`.

Not addressed:
- Add CI/CD (GitHub Actions, pytest, ruff/lint)
- Replace manual test scripts with pytest framework
- Add more admin commands (peer management, server config, etc.)
- Legacy C2C handshake support could be removed (marked as discontinued)
- Type annotations more consistent throughout the codebase

Notes:
- `multi_client_test --handshake` calls `do_c2c_handshake` on both peers simultaneously; the DH handshake derives keys with initiator-ordered session context, so simultaneous double-init yields mismatched keys. Staggered (one initiator, one responder) handshakes work correctly.

---

# Second Review — Security & Correctness Fixes

> All items below are ✅ FIXED in the working tree, with regression tests in `tests/test_fixes.py` and CI in `.github/workflows/ci.yml`.

## CRITICAL

1. **RCE via `eval()` on server-supplied handshake config** — `dosp/client.py`
   ✅ Replaced with `ast.literal_eval` in `_parse_handshake_config()`; a malicious
   server can no longer execute code on the client (raises `HandshakeError`).

2. **Admin privilege persisted across disconnects** — `dosp/server/base.py`
   ✅ `_admin_clients` is now discarded in both `handle_client` teardown and
   `on_disconnect`, so a recycled VIP no longer inherits admin rights.

## HIGH

3. **Unsalted `sha256(user:pass)` admin token** — `dosp/protocol.py`
   ✅ `generate_admin_token` now uses PBKDF2-HMAC-SHA256 (200k iterations) with a
   per-user salt. `verify_admin_token` does constant-time verification and still
   accepts legacy plain tokens.

4. **AES-GCM nonce reuse via `Packet.to_bytes` cache / payload mutation**
   ✅ Encrypted packets are never cached, the plaintext payload is no longer
   overwritten with ciphertext, and each encode produces a fresh nonce.

5. **Legacy plaintext-key C2C handshake** — `dosp/client.py`
   ✅ Removed. `do_c2c_handshake(use_dh=False)` now raises; at-rest legacy send
   path and the responder's legacy branch are gone (DH/X25519 only).

## MEDIUM

6. **Dead decryption branch in `Packet.from_socket`** — `dosp/protocol.py`
   ✅ Removed the unreachable `encryption_key` code path; decryption is handled
   by `TunneledClient`. The unused parameter was dropped.

7. **Admin CLI stalled ~10 s per command** — `dosp/client.py`
   ✅ `_receive_response` reads the socket directly when no application receive
   loop is active, instead of waiting out the queue timeout. Verified end-to-end.

8. **Duplicate disconnect notification** — `dosp/server/base.py`
   ✅ Exit metadata is stored on the client and `on_disconnect` announces each
   VIP exactly once (guarded by `_disconnect_notified`), covering EXIT, kick and
   `stop()` races.

9. **Idle clients dropped by default `socket_timeout=30`** — `dosp/server/base.py`
   ✅ Default is now `0.0` (blocking, no idle eviction); TCP `SO_KEEPALIVE` is
   enabled and a timeout is handled as a graceful disconnect. A non-zero value
   is an explicit idle timeout.

## LOW / cleanup

10. **No send lock on `Client`** — ✅ `Client._send_all` serializes writes; tunnels
    share the same lock via `TunneledClient(send_lock=...)`.
11. **Legacy handshake error never delivered** — ✅ moot: legacy path removed.
12. **`RQIP` could insert `None` into `clients`** — ✅ guarded; returns an error.
13. **`_next_ip` unbounded** — ✅ raises `VNetError` once the template is full.
14. **`Packet.__str__` KeyError on unknown types** — ✅ uses `packetTypes.get`.
15. **`check_connection()` empty WS frame** — ✅ WebSocket path uses a `closed`
    property instead of sending an empty frame.
16. **`start()`/`stop()` not restartable** — ✅ `start()` resets `running` and
    recreates the listening socket if closed.
17. **`get_client_hash` docstring overclaimed** — ✅ reworded as an identifier,
    not a secret.
18. **No tests / lint / CI** — ✅ added `tests/test_fixes.py` (pytest) and
    `.github/workflows/ci.yml` (Python 3.10–3.13). Linting (ruff) still TODO.
