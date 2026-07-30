import logging
import socket
import threading
import time
from hashlib import sha256

from dataclasses import dataclass, field

from dosp.protocol import *
from dosp.protocol import ENABLE_COMPRESSION
from dosp.iptools import ip_to_int, int_to_ip
from dosp.ws_transport import (
    WebSocketTransport,
    WSServerConfig,
    ws_available,
    create_ws_server_transport,
)

class RemoteServer:
    def __init__(self, host: str, port: int, ip_template: str, hop_count: int = 0, source_peer_idx: int | None = None):
        self.host = host
        self.port = int(port)
        self.ip_template = ip_template
        self.hop_count = int(hop_count)
        self.source_peer_idx = source_peer_idx

    def address(self) -> tuple[str, int]:
        return self.host, self.port

    def to_bytes(self) -> bytes:
        host_b = self.host.encode()
        tmpl_b = self.ip_template.encode()
        return bytes([len(host_b)]) + host_b + self.port.to_bytes(2, 'big') + bytes([len(tmpl_b)]) + tmpl_b + bytes(
            [self.hop_count & 0xFF])

    @staticmethod
    def from_bytes(buf: bytes, offset: int = 0) -> tuple['RemoteServer', int]:
        if offset >= len(buf):
            raise ValueError("buffer underflow")
        hl = buf[offset]
        offset += 1
        host = buf[offset:offset + hl].decode()
        offset += hl
        port = int.from_bytes(buf[offset:offset + 2], 'big')
        offset += 2
        tl = buf[offset]
        offset += 1
        tmpl = buf[offset:offset + tl].decode()
        offset += tl
        hop = buf[offset] if offset < len(buf) else 0
        offset += 1
        return RemoteServer(host, port, tmpl, hop_count=hop), offset


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 7744
    ip_template: str = "7.10.0.x"

    allow_local: bool = False
    allow_compression: bool = ENABLE_COMPRESSION
    peers: list[dict] = field(default_factory=list)
    remote_servers_limit: int = 64
    max_hops: int = 8
    banned_ip_list: list[int] = field(default_factory=lambda: [ip_to_int("0.0.0.0"), ip_to_int("127.0.0.1")])
    clients_conf: list = field(default_factory=lambda: [
        0x02,  # Version
        0x0000,  # Server token (allows to determine what types after 0x1F is)
    ])
    logger_name: str | None = None

    # Admin
    admin_tokens: list[str] = field(default_factory=list)
    banned_hashes: list[str] = field(default_factory=list)
    whitelist_hashes: list[str] = field(default_factory=list)
    hash_whitelist_enabled: bool = False
    admin_token_file: str | None = None

    # WSS (WebSocket Secure)
    wss_enabled: bool = False
    wss_port: int = 7745
    wss_certfile: str | None = None
    wss_keyfile: str | None = None
    wss_keyfile_password: str | None = None


class DoSP:
    running = True
    dev_mode = False

    logger: logging.Logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    thread = None

    # ---- Peer helpers ----
    @staticmethod
    def _ip_matches_template(ip_int: int, template: str) -> bool:
        if "x" not in template:
            return False
        if "{x}" in template:
            template = template.replace("{x}", "x")

        try:
            parts = template.split('.')
            if len(parts) != 4:
                return False
            ip_s = int_to_ip(ip_int)
            if ip_s is None:
                return False
            ip_parts = ip_s.split('.')
            for i in range(4):
                if parts[i] == 'x':
                    continue
                if parts[i] != ip_parts[i]:
                    return False
            return True
        except Exception:
            return False

    @staticmethod
    def _template_prefix(template: str) -> str:
        # returns first three octets as string for quick compare, e.g. '66.11.5.'
        parts = template.split('.')
        if len(parts) != 4:
            return ''
        return '.'.join(parts[:3]) + '.'

    def __init__(self, config: ServerConfig | dict | None = None, **kwargs):
        """
        Basic DoSP server with functionality to process all packets and client connections.
        """
        if config is None:
            self.config = ServerConfig(**kwargs)
        elif isinstance(config, dict):
            self.config = ServerConfig(**(config | kwargs))
        else:
            self.config = config

        if "{x}" in self.config.ip_template:
            self.config.ip_template = self.config.ip_template.replace("{x}", "x")

        # Normalize existing peers in config
        for peer in self.config.peers:
            if "{x}" in peer.get("ip_template", ""):
                peer["ip_template"] = peer["ip_template"].replace("{x}", "x")

        # Configure instance logger
        try:
            if self.config.logger_name:
                self.logger = logging.getLogger(self.config.logger_name)
        except Exception:
            pass

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.wss_sock = None
        self._wss_server_config = None
        if self.config.wss_enabled:
            if not ws_available():
                raise ImportError(
                    "WSS enabled but simple-websocket is not installed. "
                    "Install it with: pip install simple-websocket"
                )
            self._wss_server_config = WSServerConfig(
                port=self.config.wss_port,
                host=self.config.host,
                certfile=self.config.wss_certfile,
                keyfile=self.config.wss_keyfile,
                keyfile_password=self.config.wss_keyfile_password,
            )
        self.host = self.config.host
        self.port = self.config.port
        self.clients: dict[int, RemoteClient] = {}
        self.lock = threading.Lock()
        self.assigned_ids = set()

        # Peer servers state
        self.peers: list[dict] = []  # each: {host, port, ip_template, sock?, lock?}
        self.peer_socks: list[socket.socket | None] = []
        self.peer_locks: list[threading.Lock] = []
        self.remote_servers: dict[str, RemoteServer] = {}  # ip_template -> RemoteServer metadata
        self.peer_retry_counts: list[int] = []  # retry counters per peer

        self.server_ip = ip_to_int(self.config.ip_template.replace("x", "1"))

        # Registry for templates
        self.direct_templates: dict[str, int] = {}  # ip_template -> direct peer index
        self.learned_next_hops: dict[str, list[int]] = {}  # ip_template -> [peer_idx]

        # Admin state
        self._admin_clients: set[int] = set()  # set of vip_int that are authed as admin
        self.admin_token_auto: str | None = None

        # Server lifetime counters
        self.server_packets_received: int = 0
        self.server_packets_sent: int = 0

        # Auto-generate admin token if none configured
        if not self.config.admin_tokens:
            import secrets
            self.admin_token_auto = secrets.token_hex(16)
            self.config.admin_tokens = [self.admin_token_auto]
            self.logger.info(f"Auto-generated admin token: {self.admin_token_auto}")
            if self.config.admin_token_file:
                try:
                    with open(self.config.admin_token_file, "w") as f:
                        f.write(self.admin_token_auto)
                except Exception as e:
                    self.logger.warning(f"Could not write admin token file: {e}")

        # Forwarding loop-prevention TTL store: key -> remaining hops
        self._forward_ttl: dict[tuple[int, int], int] = {}  # (dst_ip, digest) -> ttl

    # ---- Peer management ----
    def add_peer_server(self, host: str, port: int = 7744, ip_template: str | None = None) -> int:
        """
        Add a peer server that serves a given ip_template, e.g. "66.11.5.x".
        Returns peer index that can be used internally. Parses IP template from server if not set (NotImplemented)
        """
        if ip_template is None:
            # ToDo: Parses IP template from server if not set
            raise NotImplementedError("ip_template must be set")

        if "{x}" in ip_template:
            ip_template = ip_template.replace("{x}", "x")

        # Avoid duplicates
        for idx, p in enumerate(self.peers):
            if p["host"] == host and p["port"] == int(port) and p["ip_template"] == ip_template:
                return idx

        peer = {"host": host, "port": int(port), "ip_template": ip_template}
        self.peers.append(peer)
        self.peer_socks.append(None)
        self.peer_locks.append(threading.Lock())
        self.peer_retry_counts.append(0)
        # Keep config in sync
        if peer not in self.config.peers:
            self.config.peers.append(peer)
        # Register as direct template owner (manual add has priority; collision: keep first)
        if ip_template not in self.direct_templates:
            idx = len(self.peers) - 1
            self.direct_templates[ip_template] = idx
        # Maintain dict of known remote servers (first wins; manual peers always recorded)
        if ip_template not in getattr(self, 'remote_servers', {}):
            if not hasattr(self, 'remote_servers'):
                self.remote_servers = {}
            self.remote_servers[ip_template] = RemoteServer(host, port, ip_template, hop_count=0)
        self.logger.info(f"Added peer server {host}:{port} for {ip_template}")
        return len(self.peers) - 1

    def _get_peer_for_ip(self, dst_ip: int, exclude_peer_idx: int | None = None) -> int | None:
        # 1) Check direct templates (configured peers)
        best_idx = None
        for tmpl, idx in self.direct_templates.items():
            if self._ip_matches_template(dst_ip, tmpl):
                if exclude_peer_idx is not None and idx == exclude_peer_idx:
                    continue
                best_idx = idx
                break
        if best_idx is not None:
            return best_idx
        # Fallback: scan peers list as a safety (legacy)
        for idx, peer in enumerate(self.peers):
            if self._ip_matches_template(dst_ip, peer.get("ip_template", "")):
                if exclude_peer_idx is not None and idx == exclude_peer_idx:
                    continue
                return idx
        # 2) Check learned next-hops (chained routing)
        selected = None
        selected_hops = 1_000_000
        for tmpl, hops in self.learned_next_hops.items():
            if not self._ip_matches_template(dst_ip, tmpl) or not hops:
                continue
            # prefer lowest hop_count according to remote_servers meta
            rs = self.remote_servers.get(tmpl)
            hop_metric = rs.hop_count if rs else 99
            for idx in hops:
                if exclude_peer_idx is not None and idx == exclude_peer_idx:
                    continue
                if hop_metric < selected_hops:
                    selected = idx
                    selected_hops = hop_metric
        return selected

    def _ensure_peer_connected(self, idx: int) -> socket.socket | None:
        psock = self.peer_socks[idx]
        if psock is not None:
            try:
                # no explicit check; assume valid until send fails
                return psock
            except Exception:
                pass
        peer = self.peers[idx]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((peer["host"], peer["port"]))
            # Start a background reader to drain any responses
            threading.Thread(target=self._peer_reader, args=(idx, s), daemon=True).start()
            self.peer_socks[idx] = s
            self.peer_retry_counts[idx] = 0
            self.logger.info(f"Connected to peer {peer['host']}:{peer['port']} for {peer['ip_template']}")
            # send our advertisements
            try:
                self._send_advertisement(idx)
            except Exception as e:
                self.logger.debug(f"Advertise to peer[{idx}] failed: {e}")
            return s
        except Exception as e:
            self.logger.error(f"Failed to connect to peer {peer['host']}:{peer['port']}: {e}")
            try:
                s.close()
            except Exception:
                pass
            self.peer_socks[idx] = None
            return None

    def _peer_reader(self, idx: int, s: socket.socket):
        """Read packets from peer. Handle SD and S2C forwarding with loop prevention."""
        try:
            while self.running:
                pkt = Packet.from_socket(s)
                if pkt is None:
                    break
                if pkt.type == SD:
                    try:
                        self._handle_advertisement(idx, pkt.payload)
                    except Exception as e:
                        self.logger.debug(f"Failed to handle advertisement from peer[{idx}]: {e}")
                    continue
                if pkt.type == S2C:
                    dst_ip = pkt.dst_ip
                    src_ip = pkt.src_ip or 0
                    delivered = False
                    with self.lock:
                        dst_rc = self.clients.get(dst_ip)
                    if dst_rc:
                        try:
                            dst_rc.send(Packet(S2C, pkt.payload, dst_ip=dst_ip, src_ip=src_ip))
                            delivered = True
                        except Exception as e:
                            self.logger.error(f"Failed to deliver from peer[{idx}] to local {int_to_ip(dst_ip)}: {e}")
                    if not delivered:
                        self._forward_s2c(dst_ip, src_ip, pkt.payload, exclude_peer_idx=idx)
                    continue
                if pkt.type == ERR:
                    self.logger.warning(f"Peer[{idx}] sent ERR: {pkt.payload}")
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
            if idx < len(self.peer_socks) and self.peer_socks[idx] is s:
                self.peer_socks[idx] = None
            # Cleanup learned next-hops that depended on this peer
            try:
                self._on_peer_down(idx)
            except Exception:
                pass

    def _candidate_peers_for_ip(self, dst_ip: int, exclude_peer_idx: int | None = None) -> list[int]:
        """Returns list of candidate peers (other servers) who can contain given IP address (client)."""
        candidates: list[int] = []
        # Direct templates first
        for tmpl, idx in self.direct_templates.items():
            if self._ip_matches_template(dst_ip, tmpl):
                if exclude_peer_idx is None or idx != exclude_peer_idx:
                    candidates.append(idx)
                    break
        # Legacy scan as fallback
        for idx, peer in enumerate(self.peers):
            if self._ip_matches_template(dst_ip, peer.get("ip_template", "")):
                if (exclude_peer_idx is None or idx != exclude_peer_idx) and idx not in candidates:
                    candidates.append(idx)
        # Learned next-hops sorted by hop metric
        ranked: list[tuple[int, int]] = []
        for tmpl, hops in self.learned_next_hops.items():
            if not self._ip_matches_template(dst_ip, tmpl):
                continue
            rs = self.remote_servers.get(tmpl)
            hop_metric = rs.hop_count if rs else 99
            for idx in hops:
                if (exclude_peer_idx is None or idx != exclude_peer_idx) and idx not in candidates:
                    ranked.append((hop_metric, idx))
        ranked.sort(key=lambda x: x[0])
        candidates.extend([idx for _, idx in ranked])
        return candidates

    @staticmethod
    def _pkt_digest(payload: bytes) -> int:
        try:
            return int.from_bytes(sha256(payload[:64]).digest()[:4], 'big')
        except Exception:
            return 0

    def _ttl_left(self, dst_ip: int, digest: int) -> int:
        return self._forward_ttl.get((dst_ip, digest), self.config.max_hops)

    def _decrement_ttl(self, dst_ip: int, digest: int) -> int:
        left = self._ttl_left(dst_ip, digest)
        left = max(0, left - 1)
        self._forward_ttl[(dst_ip, digest)] = left
        return left

    def _forward_s2c(self, dst_ip: int, src_ip: int, payload: bytes, exclude_peer_idx: int | None = None) -> bool:
        """
        Try to forward S2C packet to another peer. Returns True if forwarded.
        Avoids sending back to exclude_peer_idx. Honors TTL.
        """
        digest = self._pkt_digest(payload)
        if self._ttl_left(dst_ip, digest) <= 0:
            self.logger.debug(f"Dropping S2C to {int_to_ip(dst_ip)} due to TTL=0")
            return False
        for peer_idx in self._candidate_peers_for_ip(dst_ip, exclude_peer_idx=exclude_peer_idx):
            psock = self._ensure_peer_connected(peer_idx)
            if psock is None:
                continue
            try:
                with self.peer_locks[peer_idx]:
                    psock.sendall(Packet(S2C, payload, dst_ip=dst_ip, src_ip=src_ip).to_bytes())
                self._decrement_ttl(dst_ip, digest)
                try:
                    self.logger.info(
                        f"FWD S2C peer[{peer_idx}] {int_to_ip(src_ip)} -> {int_to_ip(dst_ip)} (ttl {self._ttl_left(dst_ip, digest)})")
                except Exception:
                    self.logger.info(
                        f"FWD S2C peer[{peer_idx}] -> {int_to_ip(dst_ip)} (ttl {self._ttl_left(dst_ip, digest)})")
                return True
            except Exception as e:
                self.logger.error(f"Peer[{peer_idx}] send failed: {e}")
                try:
                    psock.close()
                except Exception:
                    pass
                self.peer_socks[peer_idx] = None
                # try next candidate
                continue
        return False

    def _build_advertisement_payload(self) -> bytes:
        try:
            entries: list[RemoteServer] = []
            # Our own template (hop 0)
            entries.append(RemoteServer(self.host, self.port, self.ip_template, hop_count=0))
            # Advertise direct peers (hop 1 via us)
            for tmpl, peer_idx in self.direct_templates.items():
                if tmpl == self.ip_template:
                    continue
                if 0 <= peer_idx < len(self.peers):
                    p = self.peers[peer_idx]
                    entries.append(RemoteServer(p["host"], int(p["port"]), tmpl, hop_count=1))
            # Encode: ver(1) | count(1) | entries
            ver = 1
            buf = bytes([ver, len(entries) & 0xFF])
            for e in entries:
                buf += e.to_bytes()
            return buf
        except Exception as e:
            self.logger.debug(f"Failed to build advertisement: {e}")
            return b"\x01\x00"

    def _send_advertisement(self, peer_idx: int) -> None:
        if peer_idx < 0 or peer_idx >= len(self.peer_socks):
            return
        psock = self.peer_socks[peer_idx]
        if not psock:
            return
        payload = self._build_advertisement_payload()
        try:
            with self.peer_locks[peer_idx]:
                psock.sendall(Packet(SD, payload).to_bytes())
        except Exception as e:
            self.logger.debug(f"Sending advertisement to peer[{peer_idx}] failed: {e}")

    def _handle_advertisement(self, sender_idx: int, payload: bytes) -> None:
        try:
            if not payload:
                return
            ver = payload[0]
            if ver != 1:
                return
            if len(payload) < 2:
                return
            count = payload[1]
            offset = 2
            for _ in range(count):
                rs, offset = RemoteServer.from_bytes(payload, offset)
                tmpl = rs.ip_template
                # Collision: first wins
                if tmpl in self.direct_templates or tmpl in self.learned_next_hops:
                    continue
                # If hop_count==0, sender claims ownership. If capacity allows, register direct via sender peer.
                if rs.hop_count == 0 and len(self.direct_templates) < self.config.remote_servers_limit:
                    self.direct_templates[tmpl] = sender_idx
                    # Track metadata
                    self.remote_servers[tmpl] = RemoteServer(self.peers[sender_idx]["host"],
                                                             int(self.peers[sender_idx]["port"]), tmpl, hop_count=0,
                                                             source_peer_idx=sender_idx)
                    self.logger.info(f"Learned direct owner for {tmpl} via peer[{sender_idx}]")
                    continue
                # Otherwise store as learned next-hop (chain via sender)
                self.learned_next_hops.setdefault(tmpl, [])
                if sender_idx not in self.learned_next_hops[tmpl]:
                    self.learned_next_hops[tmpl].append(sender_idx)
                    self.remote_servers[tmpl] = RemoteServer(self.peers[sender_idx]["host"],
                                                             int(self.peers[sender_idx]["port"]), tmpl,
                                                             hop_count=rs.hop_count + 1, source_peer_idx=sender_idx)
                    self.logger.debug(f"Learned next-hop for {tmpl} via peer[{sender_idx}] (hop {rs.hop_count + 1})")
        except Exception as e:
            self.logger.debug(f"Advertisement parse error from peer[{sender_idx}]: {e}")

    def _on_peer_down(self, peer_idx: int) -> None:
        # Remove next-hop entries containing this peer
        to_delete = []
        for tmpl, hops in self.learned_next_hops.items():
            if peer_idx in hops:
                hops = [h for h in hops if h != peer_idx]
                if hops:
                    self.learned_next_hops[tmpl] = hops
                else:
                    to_delete.append(tmpl)
        for tmpl in to_delete:
            self.learned_next_hops.pop(tmpl, None)
            self.remote_servers.pop(tmpl, None)

    def _next_ip(self) -> tuple[int, int]:
        """
         Gives the next vIP available address.
         :returns: ip_int, ip_num (`x` from preset)
        """
        with self.lock:
            ip_num = 2
            while True:
                if ip_num not in self.assigned_ids:
                    ip_str = self.config.ip_template.replace("x", str(ip_num))
                    ip_int = ip_to_int(ip_str)
                    if ip_int not in self.clients:
                        self.assigned_ids.add(ip_num)
                        return ip_int, ip_num
                ip_num += 1

    def start(self, detach: bool = False) -> threading.Thread | None:
        """
        Start server socket.
        :param detach: Run as Thread or not (if False locks code execution).
        :return: Thread if detach else None
        """
        # Initialize configured peers
        try:
            for peer in list(self.config.peers):
                try:
                    self.add_peer_server(peer["host"], peer["port"], peer["ip_template"])
                except Exception as e:
                    self.logger.error(f"Failed to add peer {peer}: {e}")
        except Exception as e:
            self.logger.error(f"Peer init error: {e}")

        def _accept_wss():
            if not self._wss_server_config:
                return
            wss_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            wss_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            wss_sock.bind((self.config.host, self.config.wss_port))
            wss_sock.listen()
            self.wss_sock = wss_sock
            proto = "WSS" if self.config.wss_certfile else "WS"
            self.logger.info(f"{proto} listening on {self.config.host}:{self.config.wss_port}")
            while self.running:
                try:
                    client_sock, addr = wss_sock.accept()
                    transport = create_ws_server_transport(
                        client_sock, addr, self._wss_server_config
                    )
                    threading.Thread(
                        target=self.handle_client, args=(transport,), daemon=True
                    ).start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"WSS accept error: {e}")

        def bind() -> None:
            self.sock.bind((self.config.host, self.config.port))
            self.sock.listen()
            self.logger.info(f"Server listening on {self.config.host}:{self.config.port}")
            while self.running:
                try:
                    client_sock, addr = self.sock.accept()
                    threading.Thread(target=self.handle_client, args=(client_sock,), daemon=True).start()
                except KeyboardInterrupt:
                    self.logger.info("Server stopped by user")
                    self.stop()
                    break
                except Exception as e:
                    self.logger.error(f"Accept error: {e}")

        if not detach:
            if self._wss_server_config:
                threading.Thread(target=_accept_wss, daemon=True).start()
            bind()
            return None

        if self.thread and self.thread.is_alive():
            return self.thread

        self.thread = threading.Thread(target=bind, daemon=True)
        if self._wss_server_config:
            self._wss_thread = threading.Thread(target=_accept_wss, daemon=True)
            self._wss_thread.start()
        self.thread.start()
        return self.thread

    def stop(self):
        """sends a close packet to all clients and stops the server"""
        for client in self.clients.values():
            client.send(Packet(EXIT, b""))
        # Close peer sockets
        try:
            for psock in list(getattr(self, 'peer_socks', []) or []):
                try:
                    if psock:
                        psock.close()
                except Exception:
                    pass
        except Exception:
            pass
        self.sock.close()
        if self.wss_sock:
            try:
                self.wss_sock.close()
            except Exception:
                pass
        self.running = False

    def handle_client(self, sock: socket.socket):
        """
        Handles a single client connection.

        This function is run in a separate thread for each client connection.
        It assigns a virtual IP address to the client and sends it to the client.
        Then it enters a loop where it receives packets from the client and
        calls `handle_packet` to process them.

        If the client forcibly closes the connection, a `ConnectionResetError`
        is raised and caught. The client's virtual IP address is then removed
        from the server's internal state.

        If any other exception is raised, it is caught and logged, and the
        client's virtual IP address is removed from the server's internal state.

        :param sock: The socket object of the client connection.
        """
        ip_int, ip_id = self._next_ip()
        with self.lock:
            self.clients[ip_int] = RemoteClient(sock, ip_int, self.logger)
        try:
            self.on_connect(sock, ip_int)
            while True:
                # Check for pending disconnect before blocking on recv
                with self.lock:
                    rc = self.clients.get(ip_int)
                    if rc is None or rc.should_disconnect:
                        break
                pkt = Packet.from_socket(sock, src_ip=ip_int)
                if pkt is None:
                    break
                self.handle_packet(pkt, sock, ip_int)
        except ConnectionResetError:
            self.logger.info(f"Client {int_to_ip(ip_int)} forcibly closed the connection")
        except Exception as e:
            self.logger.error(f"Error with client {int_to_ip(ip_int)}: {e}")
        finally:
            if sock:
                sock.close()
            with self.lock:
                self.clients.pop(ip_int, None)
                self.assigned_ids.discard(ip_id)
            self.on_disconnect(ip_int)

    def on_connect(self, sock: socket.socket, ip_int: int):
        self.logger.info(f"Client connected: {int_to_ip(ip_int)}")
        with self.lock:
            rc = self.clients.get(ip_int)
            if rc:
                rc.connected_at = time.time()
        if sock is not None:
            pkt_aip = Packet(AIP, ip_int.to_bytes(4, 'big'))
            pkt_hsk = Packet(HSK, self.config.allow_compression.to_bytes() + str(self.config.clients_conf).encode())
            try:
                sock.sendall(pkt_aip.to_bytes())
                sock.sendall(pkt_hsk.to_bytes())
            except Exception as e:
                self.logger.error(f"Failed to send IP or config to {int_to_ip(ip_int)}: {e}")

    def local_connect(self, client):
        """Connects a local client to the server without using sockets. WIP"""
        if not (self.running and self.config.allow_local):
            raise HandshakeError("server is not running or allow_local is disabled")

        ip_int, ip_id = self._next_ip()
        with self.lock:
            self.clients[ip_int] = RemoteClient(None, ip_int, self.logger, allow_local=True)
        try:
            self.on_connect(None, ip_int)
            return ip_int
        except Exception as e:
            self.logger.error(f"Local connection failed: {e}")
            with self.lock:
                self.clients.pop(ip_int, None)
                self.assigned_ids.discard(ip_id)
            raise HandshakeError("local connection failed")

    def on_disconnect(self, ip_int: int, code: str = "", reason: str = None):
        self.logger.info(f"Client disconnected: {int_to_ip(ip_int)}")
        label_map = {
            "CC": "Just exited",
            "EX": "ProcessExit",
            "UE": "UnexpectedError",
            "": "No code provided",
        }
        label = label_map.get(code, f"unknown code ({code})")
        if reason:
            self.logger.info(f"Client {int_to_ip(ip_int)} disconnected: {reason} ({label})")
        else:
            self.logger.info(f"Client {int_to_ip(ip_int)} disconnected: {label}")

    def on_function(self, function_name: str, ip_int: int) -> tuple[bool, str]:
        self.logger.info(f"Running function from {int_to_ip(ip_int)}: {function_name}")
        return False, "Not enabled"

    def _is_admin(self, ip_int: int) -> bool:
        return ip_int in self._admin_clients

    def _check_banned_hash(self, client_hash: str) -> bool:
        if not client_hash:
            return False
        if self.config.hash_whitelist_enabled:
            return client_hash not in self.config.whitelist_hashes
        return client_hash in self.config.banned_hashes

    def _broadcast(self, payload: bytes, exclude_ip: int | None = None) -> int:
        """Send a packet to all connected clients. Returns count of recipients."""
        count = 0
        with self.lock:
            for vip, rc in list(self.clients.items()):
                if exclude_ip is not None and vip == exclude_ip:
                    continue
                try:
                    rc.send(Packet(MSG, payload))
                    rc.packets_sent += 1
                    self.server_packets_sent += 1
                    count += 1
                except Exception as e:
                    self.logger.error(f"Broadcast to {int_to_ip(vip)} failed: {e}")
        return count

    def _force_disconnect(self, rc: RemoteClient) -> None:
        """Force-disconnect a client: send EXIT, close socket, mark for removal."""
        try:
            rc.send(Packet(EXIT, b"Disconnected by admin"))
        except Exception:
            pass
        rc.should_disconnect = True
        if rc.sock is not None:
            try:
                rc.sock.close()
            except Exception:
                pass
            rc.sock = None

    def _handle_admin_command(self, payload: bytes, ip_int: int) -> str:
        """Process an admin command payload. Returns response string."""
        cmd = payload.decode(errors='ignore').strip()
        parts = cmd.split()
        if not parts:
            return "ERR:Empty command"

        command = parts[0].lower()
        args = parts[1:]

        if command == "help":
            return (
                "Commands:\n"
                "  help                     - this help\n"
                "  clients                  - list connected clients\n"
                "  client <vip>             - show client details\n"
                "  kick <vip>               - disconnect a client\n"
                "  ban <vip>                - ban client by hash\n"
                "  unban <hash>             - remove hash from ban list\n"
                "  whitelist <hash>         - add hash to whitelist\n"
                "  whitelist-remove <hash>  - remove hash from whitelist\n"
                "  whitelist-on             - enable whitelist-only mode\n"
                "  whitelist-off            - disable whitelist-only mode\n"
                "  block <vip>              - block a VIP address\n"
                "  unblock <vip>            - unblock a VIP address\n"
                "  stats                    - server & per-client packet stats\n"
                "  broadcast <message>      - send message to all clients\n"
                "  exit                     - disconnect admin session"
            )

        elif command == "clients":
            with self.lock:
                if not self.clients:
                    return "No clients connected"
                lines = []
                for vip, rc in sorted(self.clients.items()):
                    ip_s = int_to_ip(vip)
                    admin_tag = " [ADMIN]" if rc.is_admin else ""
                    hash_preview = rc.client_hash[:16] + "..." if rc.client_hash else "N/A"
                    uptime = int(time.time() - rc.connected_at) if rc.connected_at else 0
                    lines.append(
                        f"  {ip_s}{admin_tag}  hash={hash_preview}  "
                        f"uptime={uptime}s  rx={rc.packets_received}  tx={rc.packets_sent}"
                    )
                return f"Clients ({len(self.clients)}):\n" + "\n".join(lines)

        elif command == "client":
            if not args:
                return "ERR:Usage: client <vip>"
            try:
                target_ip = ip_to_int(args[0])
            except Exception:
                return f"ERR:Invalid VIP: {args[0]}"
            with self.lock:
                rc = self.clients.get(target_ip)
            if not rc:
                return f"ERR:Client {args[0]} not found"
            return (
                f"Client {int_to_ip(target_ip)}:\n"
                f"  Hash: {rc.client_hash or 'N/A'}\n"
                f"  Admin: {rc.is_admin}\n"
                f"  Connected: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(rc.connected_at)) if rc.connected_at else 'N/A'}\n"
                f"  Packets received: {rc.packets_received}\n"
                f"  Packets sent: {rc.packets_sent}\n"
                f"  Should disconnect: {rc.should_disconnect}"
            )

        elif command == "kick":
            if not args:
                return "ERR:Usage: kick <vip>"
            try:
                target_ip = ip_to_int(args[0])
            except Exception:
                return f"ERR:Invalid VIP: {args[0]}"
            with self.lock:
                rc = self.clients.get(target_ip)
            if not rc:
                return f"ERR:Client {args[0]} not found"
            self._force_disconnect(rc)
            return f"Client {args[0]} kicked"

        elif command == "ban":
            if not args:
                return "ERR:Usage: ban <vip>"
            try:
                target_ip = ip_to_int(args[0])
            except Exception:
                return f"ERR:Invalid VIP: {args[0]}"
            with self.lock:
                rc = self.clients.get(target_ip)
            if not rc or not rc.client_hash:
                return f"ERR:Client {args[0]} has no hash or not found"
            h = rc.client_hash
            if h not in self.config.banned_hashes:
                self.config.banned_hashes.append(h)
            self._force_disconnect(rc)
            return f"Client {args[0]} banned (hash: {h[:16]}...)"

        elif command == "unban":
            if not args:
                return "ERR:Usage: unban <hash>"
            h = args[0]
            if h in self.config.banned_hashes:
                self.config.banned_hashes.remove(h)
                return f"Hash {h[:16]}... removed from ban list"
            return "ERR:Hash not in ban list"

        elif command == "whitelist":
            if not args:
                return "ERR:Usage: whitelist <hash>"
            h = args[0]
            if h not in self.config.whitelist_hashes:
                self.config.whitelist_hashes.append(h)
            return f"Hash {h[:16]}... added to whitelist"

        elif command == "whitelist-remove":
            if not args:
                return "ERR:Usage: whitelist-remove <hash>"
            h = args[0]
            if h in self.config.whitelist_hashes:
                self.config.whitelist_hashes.remove(h)
                return f"Hash {h[:16]}... removed from whitelist"
            return "ERR:Hash not in whitelist"

        elif command == "whitelist-on":
            self.config.hash_whitelist_enabled = True
            return "Whitelist-only mode enabled"

        elif command == "whitelist-off":
            self.config.hash_whitelist_enabled = False
            return "Whitelist-only mode disabled"

        elif command == "block":
            if not args:
                return "ERR:Usage: block <vip>"
            try:
                target_ip = ip_to_int(args[0])
            except Exception:
                return f"ERR:Invalid VIP: {args[0]}"
            if target_ip not in self.config.banned_ip_list:
                self.config.banned_ip_list.append(target_ip)
            return f"VIP {args[0]} blocked"

        elif command == "unblock":
            if not args:
                return "ERR:Usage: unblock <vip>"
            try:
                target_ip = ip_to_int(args[0])
            except Exception:
                return f"ERR:Invalid VIP: {args[0]}"
            if target_ip in self.config.banned_ip_list:
                self.config.banned_ip_list.remove(target_ip)
            return f"VIP {args[0]} unblocked"

        elif command == "stats":
            lines = [
                f"Server packets received: {self.server_packets_received}",
                f"Server packets sent:     {self.server_packets_sent}",
                f"Clients connected:       {len(self.clients)}",
                f"Banned hashes:           {len(self.config.banned_hashes)}",
                f"Whitelist hashes:        {len(self.config.whitelist_hashes)}",
                f"Whitelist mode:          {'ON' if self.config.hash_whitelist_enabled else 'OFF'}",
                f"Admin tokens configured: {len(self.config.admin_tokens)}",
            ]
            return "\n".join(lines)

        elif command == "broadcast":
            if not args:
                return "ERR:Usage: broadcast <message>"
            message = " ".join(args)
            count = self._broadcast(message.encode(), exclude_ip=ip_int)
            return f"Broadcast sent to {count} clients"

        elif command == "exit" or command == "quit":
            with self.lock:
                rc = self.clients.get(ip_int)
            if rc:
                rc.should_disconnect = True
            return "Goodbye"

        else:
            return f"ERR:Unknown command: {command}. Type 'help' for available commands."

    def handle_packet(self, pkt: Packet, sock: socket.socket, ip_int: int):
        src_ip = pkt.src_ip or ip_int
        with self.lock:
            src_rc = self.clients.get(ip_int)

        self.server_packets_received += 1
        if src_rc:
            src_rc.packets_received += 1

        def reply(p: Packet):
            if src_rc:
                src_rc.send(p)
                src_rc.packets_sent += 1
                self.server_packets_sent += 1

        if pkt.type == MSG:
            message = pkt.payload.decode(errors='ignore')
            if not message.startswith("%&DL}"):
                self.logger.info(f"[MSG] {int_to_ip(ip_int)}: {message}")
        elif pkt.type == EXIT:
            parts = pkt.payload.decode(errors='ignore').strip().split(",", 1)
            code = parts[0] if len(parts) > 0 else ""
            reason = parts[1] if len(parts) > 1 else None
            self.on_disconnect(ip_int, code=code, reason=reason)
            if src_rc:
                src_rc.should_disconnect = True
        elif pkt.type == PING:
            reply(Packet(PING, b""))
        elif pkt.type == S2C:
            dst_ip = pkt.dst_ip
            with self.lock:
                dst_rc = self.clients.get(dst_ip)
            if dst_rc:
                try:
                    dst_rc.send(Packet(S2C, pkt.payload, dst_ip=dst_ip, src_ip=src_ip))
                    dst_rc.packets_sent += 1
                    self.server_packets_sent += 1
                except Exception as e:
                    self.logger.error(f"Failed to route to {int_to_ip(dst_ip)}: {e}")
            else:
                forwarded = self._forward_s2c(dst_ip, src_ip, pkt.payload)
                if not forwarded:
                    self.logger.warning(f"No client or peer for IP {int_to_ip(dst_ip)} or TTL exhausted")
        elif pkt.type == FN:
            done, msg = self.on_function(pkt.payload.decode(), ip_int)
            if not done:
                self.logger.error(f"Function {pkt.payload.decode()} from {int_to_ip(ip_int)} failed: {msg}")
                reply(Packet(ERR, msg.encode(), src_ip=self.server_ip))
        elif pkt.type == GCL:
            self.logger.debug(f"[{int_to_ip(ip_int)}] Getting clients list")
            with self.lock:
                clients_ips = [ip.to_bytes(4, 'big') for ip in self.clients.keys()]
                payload = b"".join(clients_ips)
                reply(Packet(GCL, payload))
        elif pkt.type == CLIENT_INFO:
            if src_rc:
                hash_len = 64
                hash_val = pkt.payload[:hash_len].decode(errors='ignore')
                if hash_val:
                    src_rc.client_hash = hash_val
                    if self._check_banned_hash(hash_val):
                        self.logger.warning(
                            f"Client {int_to_ip(ip_int)} with hash {hash_val[:16]}... is banned/not-whitelisted; disconnecting"
                        )
                        reply(Packet(EXIT, b"Your client hash is blocked"))
                        if src_rc:
                            src_rc.should_disconnect = True
                    else:
                        self.logger.info(
                            f"Client {int_to_ip(ip_int)} registered hash: {hash_val[:16]}..."
                        )
        elif pkt.type == AUTH:
            if not src_rc:
                return
            token = pkt.payload.decode(errors='ignore').strip()
            if token in self.config.admin_tokens:
                self._admin_clients.add(ip_int)
                src_rc.is_admin = True
                self.logger.info(f"Client {int_to_ip(ip_int)} authenticated as admin")
                reply(Packet(AUTH, b"OK"))
            else:
                self.logger.warning(f"Failed admin auth attempt from {int_to_ip(ip_int)}")
                reply(Packet(AUTH, b"ERR:Invalid token"))
        elif pkt.type == ADMIN:
            if not src_rc:
                return
            if not self._is_admin(ip_int):
                reply(Packet(ADMIN, b"ERR:Not authenticated as admin"))
                return
            try:
                resp = self._handle_admin_command(pkt.payload, ip_int)
                reply(Packet(ADMIN, resp.encode()))
            except Exception as e:
                self.logger.error(f"Admin command error from {int_to_ip(ip_int)}: {e}")
                reply(Packet(ADMIN, f"ERR:{e}".encode()))
        elif pkt.type == BCST:
            if not src_rc:
                return
            if not self._is_admin(ip_int):
                reply(Packet(ERR, b"ERR:Admin only"))
                return
            count = self._broadcast(pkt.payload, exclude_ip=ip_int)
            self.logger.info(f"Admin {int_to_ip(ip_int)} broadcast to {count} clients")
            reply(Packet(BCST, f"Broadcast sent to {count} clients".encode()))
        elif pkt.type == SD:
            try:
                rhost, rport = sock.getpeername()
                mapped_idx = None
                for i, p in enumerate(self.peers):
                    if p.get("host") == rhost and int(p.get("port")) == int(rport):
                        mapped_idx = i
                        break
                if mapped_idx is not None:
                    self._handle_advertisement(mapped_idx, pkt.payload)
                else:
                    self.logger.debug("Received SD from unknown peer; ignoring")
            except Exception as e:
                self.logger.debug(f"Failed to handle SD from client/peer: {e}")
        elif pkt.type == RQIP:
            new_ip = int.from_bytes(pkt.payload, 'big')
            self.logger.debug(f"[{int_to_ip(ip_int)}] Requesting IP {int_to_ip(new_ip)}")
            if new_ip in self.config.banned_ip_list:
                self.logger.warning(f"IP {int_to_ip(new_ip)} is in block list")
                reply(Packet(RQIP, b"E:IP can't be used"))
                return
            if new_ip in self.assigned_ids:
                self.logger.warning(f"IP {int_to_ip(new_ip)} is already assigned to {int_to_ip(ip_int)}")
                reply(Packet(RQIP, b"E:IP already in use"))
                return
            try:
                with self.lock:
                    if ip_int in self.assigned_ids:
                        self.assigned_ids.remove(ip_int)
                    client_obj = self.clients.pop(ip_int, None)
                    self.clients[new_ip] = client_obj
                    self.assigned_ids.add(new_ip)
            except Exception as e:
                print("Failed to rewrite client id:", e)
            finally:
                self.on_disconnect(new_ip)
            reply(Packet(RQIP, b"D:"))
            reply(Packet(AIP, new_ip.to_bytes(4, 'big')))
            self.logger.debug(f"[{int_to_ip(ip_int)}] got new vIP {int_to_ip(new_ip)}")
        else:
            self.logger.warning(f"Unknown packet type {hex(pkt.type)} from {int_to_ip(ip_int)}")
            reply(Packet(ERR, bytes([ERR_CODES.UKNP])))
