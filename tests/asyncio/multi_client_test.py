import argparse
import asyncio
import os
import threading
import time
import logging
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

from dosp.client import Client
from dosp.protocol import Packet, S2C, MSG, int_to_ip, ip_to_int

try:
    # When run as a module: python -m tests.asyncio.multi_client_test
    from tests.asyncio.server_harness import ServerConfig, start_peered_servers, stop_servers, ServerProcess
except Exception:
    # When run directly from this directory
    from server_harness import ServerConfig, start_peered_servers, stop_servers, ServerProcess


@dataclass
class ClientHandle:
    idx: int
    client: Client
    vip_int: int
    vip: str
    recv_lock: threading.Lock
    received: list[bytes]
    thread: threading.Thread


def _client_recv_loop(ch: ClientHandle, stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            pkt = ch.client.receive(on_error="ignore")
            if pkt is None:
                time.sleep(0.01)
                continue
            if pkt.type == S2C:
                with ch.recv_lock:
                    ch.received.append(pkt.payload)
            elif pkt.type == MSG:
                with ch.recv_lock:
                    ch.received.append(pkt.payload)
        except Exception:
            time.sleep(0.01)


async def start_clients(n: int, addresses: List[str]) -> List[ClientHandle]:
    """
    Start n clients distributed across provided server addresses (host:port strings).
    Returns list of ClientHandle with running receiver threads.
    """
    handles: List[ClientHandle] = []
    stop_events: List[threading.Event] = []

    async def _start_one(i: int, addr: str) -> ClientHandle:
        def _open_client() -> ClientHandle:
            c = Client(host=addr)
            vip = int_to_ip(c.vip_int)
            ch = ClientHandle(
                idx=i,
                client=c,
                vip_int=c.vip_int,
                vip=vip,
                recv_lock=threading.Lock(),
                received=[],
                thread=None,  # type: ignore
            )
            return ch

        ch = await asyncio.to_thread(_open_client)
        ev = threading.Event()
        t = threading.Thread(target=_client_recv_loop, args=(ch, ev), daemon=True)
        ch.thread = t
        t.start()
        stop_events.append(ev)
        return ch

    # Round-robin assignment of addresses
    tasks = [
        _start_one(i, addresses[i % len(addresses)])
        for i in range(n)
    ]
    handles = await asyncio.gather(*tasks)
    # attach stop events list for lifecycle mgmt
    for h, ev in zip(handles, stop_events):
        setattr(h, "_stop_event", ev)
    return handles


async def stop_clients(handles: List[ClientHandle]):
    for h in handles:
        ev: threading.Event = getattr(h, "_stop_event")
        ev.set()
    # Let receiver threads wind down
    await asyncio.sleep(0.05)
    # Close clients
    def _close(h: ClientHandle):
        try:
            h.client.close()
        except Exception:
            pass
    await asyncio.gather(*[asyncio.to_thread(_close, h) for h in handles])


async def await_received(handle: ClientHandle, min_count: int, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with handle.recv_lock:
            if len(handle.received) >= min_count:
                return True
        await asyncio.sleep(0.01)
    return False


async def pairwise_handshakes(handles: List[ClientHandle]) -> None:
    """
    Perform c2c handshakes in pairs: (0<->1), (2<->3), ... For odd leftover, skip.
    """
    async def _hs(a: ClientHandle, b: ClientHandle):
        def _do(a: ClientHandle, b: ClientHandle):
            a.client.do_c2c_handshake(b.vip_int)
        await asyncio.to_thread(_do, a, b)

    tasks = []
    for i in range(0, len(handles) - 1, 2):
        tasks.append(_hs(handles[i], handles[i+1]))
        tasks.append(_hs(handles[i+1], handles[i]))
    if tasks:
        await asyncio.gather(*tasks)


async def send_pairwise_messages(handles: List[ClientHandle], payload: bytes) -> None:
    async def _send(a: ClientHandle, b: ClientHandle):
        def _do():
            a.client.send(Packet(S2C, payload, dst_ip=b.vip_int))
        await asyncio.to_thread(_do)

    tasks = []
    for i in range(0, len(handles) - 1, 2):
        a = handles[i]
        b = handles[i+1]
        tasks.append(_send(a, b))
        tasks.append(_send(b, a))
    if tasks:
        await asyncio.gather(*tasks)


async def scenario_single_server(num_clients: int, host: str, port: int, do_handshake: bool) -> int:
    # Start a dedicated server instance
    sp = ServerProcess(ServerConfig(host=host, port=port, ip_template="7.10.0.{x}"))
    sp.start(wait_ready=True)
    handles: List[ClientHandle] = []
    try:
        addr = f"{host}:{port}"
        handles = await start_clients(num_clients, [addr])
        if do_handshake:
            await pairwise_handshakes(handles)
        msg = b"hello-multi"
        await send_pairwise_messages(handles, msg)
        # Expect each client to receive exactly one message (from its pair)
        ok = 0
        for h in handles:
            if await await_received(h, 1, timeout=5.0):
                ok += 1
        return ok
    finally:
        if handles:
            await stop_clients(handles)
        stop_servers([sp])


async def scenario_two_servers(num_clients: int, base_port: int, do_handshake: bool) -> int:
    # Two peered servers, clients half on each
    s_cfgs = [
        ServerConfig(host="127.0.0.1", port=base_port, ip_template="7.10.0.{x}"),
        ServerConfig(host="127.0.0.1", port=base_port + 1, ip_template="7.20.0.{x}"),
    ]
    servers = start_peered_servers(s_cfgs, topology="all")
    try:
        addrs = [f"127.0.0.1:{base_port}", f"127.0.0.1:{base_port+1}"]
        handles = await start_clients(num_clients, addrs)
        try:
            if do_handshake:
                await pairwise_handshakes(handles)
            await send_pairwise_messages(handles, b"hello-cross")
            ok = 0
            for h in handles:
                if await await_received(h, 1, timeout=6.0):
                    ok += 1
            return ok
        finally:
            await stop_clients(handles)
    finally:
        stop_servers(servers)


async def scenario_cross(base_port: int) -> int:
    # Setup logging dirs and filters
    test_name = "cross host comunication"
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_dir = Path("logs") / test_name / ts
    log_dir.mkdir(parents=True, exist_ok=True)

    # Logging configuration: console minimal, files per-instance
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    # Clear existing handlers to avoid duplicates on repeated runs
    for h in list(root.handlers):
        root.removeHandler(h)

    class ConsoleFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            msg = record.getMessage()
            name = record.name or ""
            if record.levelno >= logging.ERROR:
                return True
            if "FWD" in msg:
                return True
            if name.startswith("client.1.") or name.startswith("client.2."):
                return True
            return False

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.addFilter(ConsoleFilter())
    ch.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(ch)

    # Prepare file handlers helper
    def add_file_handler(logger_name: str, filename: str):
        lg = logging.getLogger(logger_name)
        fh = logging.FileHandler(log_dir / filename, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        lg.addHandler(fh)
        lg.setLevel(logging.DEBUG)

    # Two servers with unidirectional peering s1->s2
    from tests.asyncio.server_harness import ServerConfig, ServerProcess
    s1 = ServerProcess(ServerConfig(host="127.0.0.1", port=base_port, ip_template="7.10.0.{x}", logger_name="server.1"))
    s2 = ServerProcess(ServerConfig(host="127.0.0.1", port=base_port + 1, ip_template="7.20.0.{x}", logger_name="server.2"))
    # configure one-way peering
    s1.add_peer("127.0.0.1", base_port + 1, "7.20.0.{x}")

    # Add file handlers for servers
    add_file_handler("server.1", "server1.log")
    add_file_handler("server.2", "server2.log")

    s1.start(wait_ready=True)
    s2.start(wait_ready=True)

    # Create two clients with per-instance loggers and receiver threads
    def open_client(addr: str, cid: int) -> ClientHandle:
        c = Client(host=addr, client_id=cid)
        vip = int_to_ip(c.vip_int)
        ch = ClientHandle(
            idx=cid,
            client=c,
            vip_int=c.vip_int,
            vip=vip,
            recv_lock=threading.Lock(),
            received=[],
            thread=None,  # type: ignore
        )
        return ch

    # Add file handlers for client tx/rx loggers
    add_file_handler("client.1.tx", "client1_tx.log")
    add_file_handler("client.1.rx", "client1_rx.log")
    add_file_handler("client.2.tx", "client2_tx.log")
    add_file_handler("client.2.rx", "client2_rx.log")

    h1 = await asyncio.to_thread(open_client, f"127.0.0.1:{base_port}", 1)
    h2 = await asyncio.to_thread(open_client, f"127.0.0.1:{base_port+1}", 2)

    stop_events: List[threading.Event] = []
    try:
        # Start receiver threads
        for h in (h1, h2):
            ev = threading.Event()
            t = threading.Thread(target=_client_recv_loop, args=(h, ev), daemon=True)
            h.thread = t
            t.start()
            stop_events.append(ev)

        def have_rx(h: ClientHandle) -> bool:
            with h.recv_lock:
                return len(h.received) > 0

        # Attempt 1: handshake then S2C from client1 -> client2
        try:
            await asyncio.to_thread(h1.client.do_c2c_handshake, h2.vip_int)
            await asyncio.sleep(0.05)
            await asyncio.to_thread(h1.client.send, Packet(S2C, b"cross-enc", dst_ip=h2.vip_int))
            ok1 = await await_received(h2, 1, timeout=6.0)
        except Exception:
            ok1 = False

        # Reset receive buffers for clarity
        with h1.recv_lock:
            h1.received.clear()
        with h2.recv_lock:
            h2.received.clear()

        # Attempt 2: no handshake, plain S2C forwarding
        try:
            await asyncio.to_thread(h1.client.send, Packet(S2C, b"cross-plain", dst_ip=h2.vip_int))
            ok2 = await await_received(h2, 1, timeout=5.0)
        except Exception:
            ok2 = False

        # Attempt 3: send MSG as well
        try:
            await asyncio.to_thread(h1.client.send, Packet(MSG, b"hello-msg", dst_ip=h2.vip_int))
            ok3 = await await_received(h2, 1, timeout=5.0)
        except Exception:
            ok3 = False

        all_ok = ok1 and ok2 and ok3
        if all_ok:
            print("cross host comunication: PASS")
            return 0
        else:
            # On failure print log dir path
            print(f"cross host comunication: FAIL. See logs at: {log_dir}")
            return 1
    finally:
        # Stop clients
        for ev in stop_events:
            ev.set()
        await asyncio.sleep(0.05)
        for h in (h1, h2):
            try:
                h.client.close()
            except Exception:
                pass
        # Stop servers
        try:
            s1.stop()
        except Exception:
            pass
        try:
            s2.stop()
        except Exception:
            pass


async def main_async(args) -> int:
    if args.mode == "single":
        ok = await scenario_single_server(args.clients, args.host, args.port, args.handshake)
        expected = args.clients if args.clients % 2 == 0 else args.clients - 1
        print(f"Single-server: received_ok={ok}/{expected}")
        return 0 if ok >= expected else 1
    elif args.mode == "two":
        ok = await scenario_two_servers(args.clients, args.port, args.handshake)
        expected = args.clients if args.clients % 2 == 0 else args.clients - 1
        print(f"Two-servers: received_ok={ok}/{expected}")
        return 0 if ok >= expected else 1
    elif args.mode == "cross":
        return await scenario_cross(args.port)
    else:
        raise SystemExit(f"Unknown mode: {args.mode}")


def parse_args():
    p = argparse.ArgumentParser(description="Asyncio multi-client DoSP test harness")
    p.add_argument("--mode", choices=["single", "two", "cross"], default=os.getenv("MODE", "single"))
    p.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.getenv("PORT", "7744")))
    p.add_argument("--clients", type=int, default=int(os.getenv("CLIENTS", "4")))
    p.add_argument("--handshake", action="store_true", help="Perform pairwise c2c handshakes before messaging")
    return p.parse_args()


def main():
    args = parse_args()
    rc = asyncio.run(main_async(args))
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
