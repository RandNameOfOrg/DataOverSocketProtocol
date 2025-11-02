import logging
import socket
import threading
from hashlib import sha256
from dosp.protocol import *

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
        return bytes([len(host_b)]) + host_b + self.port.to_bytes(2, 'big') + bytes([len(tmpl_b)]) + tmpl_b + bytes([self.hop_count & 0xFF])

    @staticmethod
    def from_bytes(buf: bytes, offset: int = 0) -> tuple['RemoteServer', int]:
        if offset >= len(buf):
            raise ValueError("buffer underflow")
        hl = buf[offset]
        offset += 1
        host = buf[offset:offset+hl].decode()
        offset += hl
        port = int.from_bytes(buf[offset:offset+2], 'big')
        offset += 2
        tl = buf[offset]
        offset += 1
        tmpl = buf[offset:offset+tl].decode()
        offset += tl
        hop = buf[offset] if offset < len(buf) else 0
        offset += 1
        return RemoteServer(host, port, tmpl, hop_count=hop), offset


class DoSP:
    running  = True
    dev_mode = False
    logger: logging.Logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    BANNED_IPs = [
        ip_to_int("0.0.0.0"),
        ip_to_int("127.0.0.1")
    ]

    # ---- Peer helpers ----
    @staticmethod
    def _ip_matches_template(ip_int: int, template: str) -> bool:
        try:
            parts = template.split('.')
            if len(parts) != 4:
                return False
            ip_s = int_to_ip(ip_int)
            if ip_s is None:
                return False
            ip_parts = ip_s.split('.')
            for i in range(4):
                if parts[i] == '{x}':
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

    config = {
        "host": "0.0.0.0",
        "port": 7744,
        "ip_template": "7.10.0.{x}",
        "allow_local": False,
        # List of peer servers: {host, port, ip_template}
        "peers": [],
        # Auto-distribution limits
        "remoteServers_limit": 64,
        # Max hops for chained forwarding (basic safeguard)
        "max_hops": 8,
        "clients_conf": [
            0x01, # Version
            0x0000, # Server token (allows to determine what types after 0x1F is)
        ]
    }

    def __init__(self, host="0.0.0.0", port=7744,
                 ip_template="7.10.0.{x}", allow_local = False, logger_name: str | None = None):
        """
        Basic DoSP server with functionality to process all packets and client connections.
        :param host: host address
        :param port: host port
        :param ip_template: what vIPs should be used for clients
        :param allow_local: allow connection from local scripts (if other scripts have access to this class)
        """
        self.host = host
        self.port = port
        self.ip_template = ip_template

        # Configure instance logger
        try:
            if logger_name:
                self.logger = logging.getLogger(logger_name)
        except Exception:
            pass

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients: dict[int, RemoteClient] = {}  # ip_int -> ServerClient
        self.lock = threading.Lock()
        self.assigned_ids = set()

        # Peer servers state
        self.peers: list[dict] = []  # each: {host, port, ip_template, sock?, lock?}
        self.peer_socks: list[socket.socket | None] = []
        self.peer_locks: list[threading.Lock] = []
        self.remote_servers: dict[str, RemoteServer] = {}  # ip_template -> RemoteServer metadata
        self.peer_retry_counts: list[int] = []  # retry counters per peer

        self.allow_local = allow_local
        self.server_ip = ip_to_int(self.ip_template.replace("{x}", "1"))
        self.config = {
            "host": self.host,
            "port": self.port,
            "ip_template": self.ip_template,
            "allow_local": self.allow_local,
            "peers": [],
            "remoteServers_limit": DoSP.config.get("remoteServers_limit", 64),
            "max_hops": DoSP.config.get("max_hops", 8),
            "clients_conf": DoSP.config["clients_conf"],
        }

        # Registry for templates
        self.direct_templates: dict[str, int] = {}  # ip_template -> direct peer index
        self.learned_next_hops: dict[str, list[int]] = {}  # ip_template -> [peer_idx]
        self.max_hops = self.config.get("max_hops", 8)
        self.remote_limit = self.config.get("remoteServers_limit", 64)
        # Forwarding loop-prevention TTL store: key -> remaining hops
        self._forward_ttl: dict[tuple[int, int], int] = {}  # (dst_ip, digest) -> ttl

    # ---- Peer management ----
    def add_peer_server(self, host: str, port: int, ip_template: str) -> int:
        """
        Add a peer server that serves a given ip_template, e.g. "66.11.5.{x}".
        Returns peer index that can be used internally.
        """
        peer = {"host": host, "port": int(port), "ip_template": ip_template}
        self.peers.append(peer)
        self.peer_socks.append(None)
        self.peer_locks.append(threading.Lock())
        self.peer_retry_counts.append(0)
        # Keep config in sync
        self.config.setdefault("peers", []).append(peer)
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
                    # Try local delivery first
                    dst_ip = pkt.dst_ip
                    src_ip = pkt.src_ip or 0
                    delivered = False
                    with self.lock:
                        dst_sock = self.clients.get(dst_ip)
                    if dst_sock and dst_sock.sock is not None:
                        try:
                            dst_sock.sock.sendall(Packet(S2C, pkt.payload, dst_ip=dst_ip, src_ip=src_ip).to_bytes())
                            delivered = True
                        except Exception as e:
                            self.logger.error(f"Failed to deliver from peer[{idx}] to local {int_to_ip(dst_ip)}: {e}")
                    if not delivered:
                        # Forward further, exclude the immediately previous peer to reduce loops
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
        return self._forward_ttl.get((dst_ip, digest), self.max_hops)

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
                    self.logger.info(f"FWD S2C peer[{peer_idx}] {int_to_ip(src_ip)} -> {int_to_ip(dst_ip)} (ttl {self._ttl_left(dst_ip, digest)})")
                except Exception:
                    self.logger.info(f"FWD S2C peer[{peer_idx}] -> {int_to_ip(dst_ip)} (ttl {self._ttl_left(dst_ip, digest)})")
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
                if rs.hop_count == 0 and len(self.direct_templates) < self.remote_limit:
                    self.direct_templates[tmpl] = sender_idx
                    # Track metadata
                    self.remote_servers[tmpl] = RemoteServer(self.peers[sender_idx]["host"], int(self.peers[sender_idx]["port"]), tmpl, hop_count=0, source_peer_idx=sender_idx)
                    self.logger.info(f"Learned direct owner for {tmpl} via peer[{sender_idx}]")
                    continue
                # Otherwise store as learned next-hop (chain via sender)
                self.learned_next_hops.setdefault(tmpl, [])
                if sender_idx not in self.learned_next_hops[tmpl]:
                    self.learned_next_hops[tmpl].append(sender_idx)
                    self.remote_servers[tmpl] = RemoteServer(self.peers[sender_idx]["host"], int(self.peers[sender_idx]["port"]), tmpl, hop_count=rs.hop_count + 1, source_peer_idx=sender_idx)
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
                    ip_str = self.ip_template.replace("{x}", str(ip_num))
                    ip_int = ip_to_int(ip_str)
                    if ip_int not in self.clients:
                        self.assigned_ids.add(ip_num)
                        return ip_int, ip_num
                ip_num += 1

    def start(self):
        # Initialize configured peers
        try:
            for peer in self.config.get("peers", []) or []:
                try:
                    self.add_peer_server(peer["host"], peer["port"], peer["ip_template"]) 
                except Exception as e:
                    self.logger.error(f"Failed to add peer {peer}: {e}")
        except Exception as e:
            self.logger.error(f"Peer init error: {e}")

        self.sock.bind((self.host, self.port))
        self.sock.listen()
        self.logger.info(f"Server listening on {self.host}:{self.port}")
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
                pkt = Packet.from_socket(sock, src_ip=ip_int)
                if pkt is None:
                    break
                self.handle_packet(pkt, sock, ip_int)
        except ConnectionResetError:
            self.logger.info(f"Client {int_to_ip(ip_int)} forcibly closed the connection")
        except Exception as e:
            self.logger.error(f"Error with client {int_to_ip(ip_int)}: {e}")
        finally:
            # try:
            if sock:
                sock.close()
            # except:
            #     pass
            with self.lock:
                self.clients.pop(ip_int, None)
                self.assigned_ids.discard(ip_id)
            self.on_disconnect(ip_int)

    def on_connect(self, sock: socket.socket, ip_int: int):
        self.logger.info(f"Client connected: {int_to_ip(ip_int)}")
        if sock is not None:
            pkt_aip = Packet(AIP, ip_int.to_bytes(4, 'big'))
            pkt_hsk = Packet(HSK, str(self.config["clients_conf"]).encode())
            try:
                sock.sendall(pkt_aip.to_bytes())
                sock.sendall(pkt_hsk.to_bytes())
            except Exception as e:
                self.logger.error(f"Failed to send IP or config to {int_to_ip(ip_int)}: {e}")

    def local_connect(self, client):
        """Connects a local client to the server without using sockets"""
        if not (self.running and self.allow_local):
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

    def on_disconnect(self, ip_int: int):
        self.logger.info(f"Client disconnected: {int_to_ip(ip_int)}")

    def on_function(self, function_name: str, ip_int: int) -> tuple[bool, str]:
        self.logger.info(f"Running function from {int_to_ip(ip_int)}: {function_name}")
        return False, "Not enabled"

    def handle_packet(self, pkt: Packet, sock: socket.socket, ip_int: int):
        src_ip = pkt.src_ip or ip_int

        if pkt.type == MSG:
            self.logger.info(f"[MSG] {int_to_ip(ip_int)}: {pkt.payload.decode(errors='ignore')}")
        elif pkt.type == EXIT:
            # TODO: Make it good
            pass
        elif pkt.type == S2C:
            dst_ip = pkt.dst_ip
            # Try local delivery first
            with self.lock:
                dst_sock = self.clients.get(dst_ip)
            if dst_sock:
                try:
                    dst_sock.sock.sendall(Packet(S2C, pkt.payload, dst_ip=dst_ip, src_ip=src_ip).to_bytes())
                except Exception as e:
                    self.logger.error(f"Failed to route to {int_to_ip(dst_ip)}: {e}")
            else:
                # Try peer forwarding (chained) with TTL and next-hop selection
                forwarded = self._forward_s2c(dst_ip, src_ip, pkt.payload)
                if not forwarded:
                    self.logger.warning(f"No client or peer for IP {int_to_ip(dst_ip)} or TTL exhausted")
        elif pkt.type == FN:
            done, msg = self.on_function(pkt.payload.decode(), ip_int)
            if not done:
                self.logger.error(f"Function {pkt.payload.decode()} from {int_to_ip(ip_int)} failed: {msg}")
                sock.sendall(Packet(ERR, msg.encode(), src_ip=self.server_ip).to_bytes())
        elif pkt.type == GCL:
            self.logger.debug(f"[{int_to_ip(ip_int)}] Getting clients list")
            with self.lock:
                clients_ips = [ip.to_bytes(4, 'big') for ip in self.clients.keys()]
                payload = b"".join(clients_ips)
                sock.sendall(Packet(GCL, payload).to_bytes())
        elif pkt.type == SD:
            # Attempt to map this socket to a known peer and ingest advertisement
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
            if new_ip in self.BANNED_IPs:
                self.logger.warning(f"IP {int_to_ip(new_ip)} is in block list")
                sock.sendall(Packet(RQIP, b"E:IP can't be used").to_bytes())
                return
            if new_ip in self.assigned_ids:
                self.logger.warning(f"IP {int_to_ip(new_ip)} is already assigned to {int_to_ip(ip_int)}")
                sock.sendall(Packet(RQIP, b"E:IP already in use").to_bytes())
                return
            try:
                with self.lock:
                    if ip_int in self.assigned_ids:
                        self.assigned_ids.remove(ip_int)
                    client_sock = self.clients.pop(ip_int, None)
                    self.clients[new_ip] = client_sock
                    self.assigned_ids.add(new_ip)
            except Exception as e:
                print("Failed to rewrite client id:", e)
            finally:
                self.on_disconnect(new_ip)
            sock.sendall(Packet(RQIP, b"D:").to_bytes())
            sock.sendall(Packet(AIP, new_ip.to_bytes(4, 'big')).to_bytes())
            self.logger.debug(f"{int_to_ip(ip_int)}] got new vIP {int_to_ip(new_ip)}")
        else:
            self.logger.warning(f"Unknown packet type {hex(pkt.type)} from {int_to_ip(ip_int)}")
            sock.sendall(Packet(ERR, bytes(int(ERR_CODES.UKNP))).to_bytes())
