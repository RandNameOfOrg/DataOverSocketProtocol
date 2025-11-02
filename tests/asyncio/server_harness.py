import socket
import threading
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional

from dosp.server import DoSP


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Poll-connect to ensure a TCP port is accepting connections."""
    deadline = time.time() + timeout
    last_err: Optional[BaseException] = None
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((host, port))
            s.close()
            return True
        except BaseException as e:
            last_err = e
            time.sleep(0.05)
        finally:
            try:
                s.close()
            except Exception:
                pass
    if last_err:
        # Best-effort debug
        try:
            import logging
            logging.getLogger(__name__).debug(f"Port {host}:{port} not ready: {last_err}")
        except Exception:
            pass
    return False


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 7744
    ip_template: str = "7.10.0.{x}"
    allow_local: bool = False
    logger_name: Optional[str] = None


class ServerProcess:
    """
    Run a DoSP server in a background thread, suitable for automated tests.

    Example:
        sp = ServerProcess(ServerConfig(port=7744, ip_template="7.10.0.{x}"))
        sp.start()
        ... run clients ...
        sp.stop()
    """

    def __init__(self, cfg: ServerConfig):
        self.cfg = cfg
        self.server = DoSP(host=cfg.host, port=cfg.port, ip_template=cfg.ip_template, allow_local=cfg.allow_local, logger_name=cfg.logger_name)
        self._thread: Optional[threading.Thread] = None

    @property
    def address(self) -> str:
        return f"{self.cfg.host}:{self.cfg.port}"

    def add_peer(self, peer_host: str, peer_port: int, peer_ip_template: str) -> None:
        # Register peer before starting, so advertisements are available early
        self.server.add_peer_server(peer_host, peer_port, peer_ip_template)

    def start(self, wait_ready: bool = True, ready_timeout: float = 5.0) -> None:
        # Ensure running flag (if server was stopped previously)
        try:
            # DoSP has class attribute running=True; if it was stopped, set True again.
            if getattr(self.server, "running", True) is False:
                setattr(self.server, "running", True)
        except Exception:
            pass

        self._thread = threading.Thread(target=self.server.start, daemon=True)
        self._thread.start()
        if wait_ready:
            _wait_for_port(self.cfg.host, self.cfg.port, timeout=ready_timeout)

    def stop(self, join_timeout: float = 2.0) -> None:
        try:
            self.server.stop()
        except Exception:
            pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)


def start_peered_servers(configs: Iterable[ServerConfig], topology: str = "all") -> List[ServerProcess]:
    """
    Start multiple DoSP servers and interconnect them as peers according to topology.

    - topology="all": full mesh (every server peers every other)
    - topology="line": linear chain (s0->s1->s2 ...)

    Returns list of ServerProcess in same order as configs.
    """
    servers = [ServerProcess(cfg) for cfg in configs]

    # Configure peering before servers are started.
    if topology == "all":
        for i, si in enumerate(servers):
            for j, sj in enumerate(servers):
                if i == j:
                    continue
                si.add_peer(sj.cfg.host, sj.cfg.port, sj.cfg.ip_template)
    elif topology == "line":
        for i in range(len(servers) - 1):
            a = servers[i]
            b = servers[i + 1]
            a.add_peer(b.cfg.host, b.cfg.port, b.cfg.ip_template)
    else:
        raise ValueError(f"Unsupported topology: {topology}")

    # Start servers
    for sp in servers:
        sp.start(wait_ready=True)

    return servers


def stop_servers(servers: Iterable[ServerProcess]) -> None:
    for sp in servers:
        sp.stop()
