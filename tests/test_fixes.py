"""Regression tests for the code-audit fixes.

Run with: pytest -q
"""

import os
import socket
import threading
import time

import pytest

from dosp import Client, Packet, MSG, S2C
from dosp.protocol import (
    encrypt,
    generate_admin_token,
    verify_admin_token,
)
from dosp.client import _parse_handshake_config
from dosp.iptools import int_to_ip, ip_to_int, ip_to_id
from dosp.server.base import DoSP, ServerConfig
from dosp.protocol import HandshakeError


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until(predicate, timeout=5.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# ---------------------------------------------------------------------------
# Admin tokens (no more unsalted sha256 / rainbow-table friendly)
# ---------------------------------------------------------------------------

def test_admin_token_roundtrip_is_deterministic():
    a = generate_admin_token("admin", "changeme")
    b = generate_admin_token("admin", "changeme")
    assert a == b
    assert a.startswith("pbkdf2_sha256$")
    assert a != generate_admin_token("admin", "changeme2")


def test_admin_token_bearer_and_password_verification():
    stored = generate_admin_token("admin", "s3cret")
    assert verify_admin_token(stored, stored) is True
    assert verify_admin_token("admin:s3cret", stored) is True
    assert verify_admin_token("admin:wrong", stored) is False
    assert verify_admin_token("", stored) is False


def test_admin_token_legacy_plain_supported():
    assert verify_admin_token("deadbeef", "deadbeef") is True
    assert verify_admin_token("deadbeef", "cafebabe") is False


# ---------------------------------------------------------------------------
# Handshake config parsing must not eval()
# ---------------------------------------------------------------------------

def test_parse_handshake_config_accepts_literal():
    comp, cfg = _parse_handshake_config(b"\x01[2, 0]")
    assert comp == 1
    assert cfg == [2, 0]


def test_parse_handshake_config_rejects_code():
    payload = b"\x00" + b"__import__('os').system('echo pwned')"
    with pytest.raises(HandshakeError):
        _parse_handshake_config(payload)


# ---------------------------------------------------------------------------
# Packet codec fixes
# ---------------------------------------------------------------------------

def test_encrypted_to_bytes_does_not_mutate_or_cache():
    key = os.urandom(32)
    p = Packet(S2C, b"hello", dst_ip=ip_to_int("7.10.0.2"),
               src_ip=ip_to_int("7.10.0.3"), encryption_key=key)
    first = p.to_bytes()
    second = p.to_bytes()
    # Plaintext must never be overwritten with ciphertext.
    assert p.payload == b"hello"
    # Fresh AES-GCM nonce on every encode => no nonce reuse.
    assert first != second
    assert first[:5] == second[:5]  # same type + length


def test_plain_to_bytes_is_cached():
    p = Packet(MSG, b"hi")
    assert p.to_bytes() is p.to_bytes()


def test_packet_str_unknown_type_does_not_raise():
    assert "0xab" in str(Packet(0xAB, b"x")).lower()


def test_mpak_roundtrip():
    subs = [
        Packet(MSG, b"a"),
        Packet(S2C, b"b", dst_ip=ip_to_int("7.10.0.9"), src_ip=ip_to_int("7.10.0.2")),
    ]
    out = Packet.multi(subs).unpack()
    assert [p.type for p in out] == [MSG, S2C]
    assert out[1].dst_ip == ip_to_int("7.10.0.9")
    assert out[1].src_ip == ip_to_int("7.10.0.2")


def test_encrypt_decrypt_roundtrip():
    from dosp.protocol import decrypt
    key = os.urandom(32)
    assert decrypt(encrypt(b"payload", key), key) == b"payload"


# ---------------------------------------------------------------------------
# iptools
# ---------------------------------------------------------------------------

def test_iptools_roundtrip_and_invalid():
    assert int_to_ip(ip_to_int("7.10.0.2")) == "7.10.0.2"
    assert ip_to_int("not-an-ip") is None
    assert int_to_ip(-1) is None
    assert ip_to_id("7.10.0.5") == 5
    assert ip_to_id(ip_to_int("7.10.0.6")) == 6


# ---------------------------------------------------------------------------
# Server-side: admin privilege reset + single disconnect notification
# ---------------------------------------------------------------------------

def test_admin_privilege_cleared_on_disconnect():
    srv = DoSP(ServerConfig(host="127.0.0.1", port=0))
    try:
        srv._admin_clients.add(12345)
        srv._disconnect_notified.discard(12345)
        srv.on_disconnect(12345)
        assert 12345 not in srv._admin_clients
    finally:
        srv.sock.close()


def test_disconnect_notified_only_once():
    srv = DoSP(ServerConfig(host="127.0.0.1", port=0))
    try:
        srv._disconnect_notified.clear()
        srv.on_disconnect(777)
        srv.on_disconnect(777)
        assert 777 in srv._disconnect_notified
        # A new client reusing the VIP must be notifiable again.
        srv._disconnect_notified.discard(777)
        srv.on_disconnect(777)
        assert 777 in srv._disconnect_notified
    finally:
        srv.sock.close()


# ---------------------------------------------------------------------------
# End-to-end: admin auth is fast (no 10s stall) and does not persist
# ---------------------------------------------------------------------------

def test_admin_auth_fast_and_not_persisted():
    port = _free_port()
    token = generate_admin_token("admin", "secret")
    srv = DoSP(ServerConfig(host="127.0.0.1", port=port, admin_tokens=[token]))
    srv.start(detach=True)
    client = None
    client2 = None
    try:
        client = Client(host="127.0.0.1", port=port)
        t0 = time.time()
        assert client.authenticate_admin(token) is True
        elapsed = time.time() - t0
        # Previously this blocked for the full receive timeout (10s).
        assert elapsed < 5
        client.close()
        client = None

        # Wait for the server to process the disconnect and free the VIP.
        time.sleep(0.3)

        client2 = Client(host="127.0.0.1", port=port)
        resp = client2.admin_command("stats")
        assert resp is not None
        assert resp.startswith("ERR:Not authenticated")
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        if client2 is not None:
            try:
                client2.close()
            except Exception:
                pass
        srv.stop()


# ---------------------------------------------------------------------------
# End-to-end: staggered DH C2C handshake + encrypted message + send lock
# ---------------------------------------------------------------------------

def test_c2c_dh_handshake_and_encrypted_message():
    port = _free_port()
    srv = DoSP(ServerConfig(host="127.0.0.1", port=port))
    srv.start(detach=True)
    c1 = c2 = None
    stop = threading.Event()
    received = []

    def pump(client):
        while not stop.is_set() and client.running:
            try:
                pkt = client.receive()
            except Exception:
                break
            if pkt is not None:
                received.append((client.vip_int, pkt))

    try:
        c1 = Client(host="127.0.0.1", port=port)
        c2 = Client(host="127.0.0.1", port=port)
        t1 = threading.Thread(target=pump, args=(c1,), daemon=True)
        t2 = threading.Thread(target=pump, args=(c2,), daemon=True)
        t1.start()
        t2.start()

        # Staggered handshake: only c1 initiates, c2 responds via its pump loop.
        c1.do_c2c_handshake(c2.vip_int)
        assert c2.vip_int in c1.tunnels  # initiator keyed by peer VIP
        assert c1.vip_int in c2.tunnels  # responder keyed by peer VIP

        c1.send(Packet(S2C, b"top-secret", dst_ip=c2.vip_int))
        assert _wait_until(
            lambda: any(
                src == c2.vip_int and p.payload == b"top-secret"
                for src, p in received
            ),
            timeout=5.0,
        ), "c2 did not receive/decrypt the tunneled message"
    finally:
        stop.set()
        for c in (c1, c2):
            if c is not None:
                try:
                    c.close()
                except Exception:
                    pass
        srv.stop()
