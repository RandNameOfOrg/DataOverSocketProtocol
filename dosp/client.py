from .protocol import *
import ast
import logging
import os
import socket
import threading
import time
from collections import deque
from queue import Queue, Empty
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from .iptools import int_to_ip, ip_to_int
from .ws_transport import ws_available, create_ws_client_transport, WebSocketTransport

if TYPE_CHECKING:
    from .server import DoSP


def _estimate_sub_size(p: Packet) -> int:
    size = 5 + len(p.payload)
    if p.type == S2C:
        size += 8
    return size


def _parse_handshake_config(payload: bytes) -> tuple[int, object]:
    """Parse an HSK payload into (compression_byte, config).

    The server-supplied config is parsed with ``ast.literal_eval`` so a
    malicious server cannot execute code on the client. Raises HandshakeError
    on invalid input.
    """
    if not payload:
        return 0, []
    compression_byte = payload[0]
    try:
        config = ast.literal_eval(payload[1:].decode())
    except (ValueError, SyntaxError) as e:
        raise HandshakeError(f"invalid handshake config from server: {e}")
    return compression_byte, config


def _split_mpak_batches(packets: list[Packet], max_chunk_size: int):
    batches = []
    current = []
    current_size = 0
    for p in packets:
        sub_size = _estimate_sub_size(p)
        if current and current_size + sub_size > max_chunk_size:
            batches.append(current)
            current = []
            current_size = 0
        current.append(p)
        current_size += sub_size
    if current:
        batches.append(current)
    return batches


class Client:
    config: dict = {}
    vip_int: int # Virtual IP
    tunnels: dict[int, TunneledClient]

    logger: logging.Logger
    sock: socket.socket | WebSocketTransport
    running: bool

    # Client identity (auto-generated, cannot be overridden)
    _client_hash: str

    def __init__(self,
                 host: str = "127.0.0.1",
                 port: int = 7744,
                 vip = None, fixed_vip = False, client_id: int | None = None,
                 require_compression = False,
                 use_ws: bool = False, ws_tls: bool = False,
                 short_s2c_threshold: int = 10,
                 short_s2c_window: float = 60.0,
                 short_s2c_cooldown: float = 60.0):
        """
        Client constructor for DoS Protocol
        :param host: DoSP server host (or host:port)
        :param port: DoSP server port
        :param vip: what vIP will be requested
        :param fixed_vip: close connection if requested vIP can not be assigned
        :param require_compression: whether to require compression, drops connection if server does not support it
        :param use_ws: use WebSocket (ws://) instead of raw TCP
        :param ws_tls: use TLS for WebSocket (wss://), requires use_ws=True
        :param short_s2c_threshold: how many short S2C frames within the window trigger an alert
        :param short_s2c_window: time window (s) for short-S2C frame counting
        :param short_s2c_cooldown: minimum delay (s) between alerts for the same peer
        """
        if ":" in host:
            try:
                host, port = host.split(":")
                port = int(port)
            except ValueError:
                raise ConnectionError("Invalid host: \"{}\"".format(host))
        self.logger = logging.getLogger(__name__)
        self._closed = False
        # Auto-generate stable client identifier (not a secret)
        self._client_hash = get_client_hash()
        # Serializes access to the connection socket so concurrent sends from
        # multiple threads cannot interleave partial frames.
        self._send_lock = threading.Lock()
        # True once receive() has been driven (i.e. an application receive loop
        # is running); admin/response calls then wait on queues instead of
        # reading the socket directly.
        self._receive_loop_active = False
        # Per-connection compression state (independent of other Client instances)
        self.compression = CompressionState()
        # MPAK unpack queue
        self._mpak_queue: list[Packet] = []
        # Pending C2C handshake responses (dispatched from receive loop)
        self._pending_c2c_responses: dict[int, Queue] = {}
        # Admin/broadcast response routing (dispatched from receive loop)
        self._response_queues: dict[int, Queue] = {}
        # Short S2C protection counters per peer
        self._short_s2c: dict[int, deque] = {}
        self._short_s2c_last_alert: dict[int, float] = {}
        self._short_s2c_threshold = max(1, int(short_s2c_threshold))
        self._short_s2c_window = max(0.0, float(short_s2c_window))
        self._short_s2c_cooldown = max(0.0, float(short_s2c_cooldown))
        # C2C tunnels (established via handshake)
        self.tunnels: dict[int, TunneledClient] = {}
        self.initializate_connection(host, port, vip=vip, fixed_vip=fixed_vip,
                                     req_compress=require_compression,
                                     use_ws=use_ws, ws_tls=ws_tls)

        self.logger.level = logging.INFO

    def initializate_connection(self,
                                host: str = "127.0.0.1",
                                port: int = 7744,
                                vip = None, fixed_vip = False, socket_params: dict = None,
                                use_ws: bool = False, ws_tls: bool = False, **kwargs):
        if use_ws:
            if not ws_available():
                raise ImportError(
                    "WebSocket requires simple-websocket. Install with: pip install simple-websocket"
                )
            scheme = "wss" if ws_tls else "ws"
            url = f"{scheme}://{host}:{port}/"
            self.logger.info(f"Connecting via {scheme}://{host}:{port}")
            self.sock = create_ws_client_transport(url)
        else:
            self.sock = socket.create_connection((host, port), **(socket_params or {}))
        self.do_handshake(vip=vip, cancel_on_RQIP_err=fixed_vip, **kwargs)
        self.running = True
        # Send client identity hash after connection
        self._send_client_info()

    def _send_all(self, data: bytes):
        """Thread-safe socket send (frames must not interleave)."""
        with self._send_lock:
            self.sock.sendall(data)

    def _send_client_info(self):
        """Send client identifier to server after connection."""
        try:
            pkt = Packet(CLIENT_INFO, self._client_hash.encode())
            self._send_all(pkt.to_bytes(self.compression))
        except Exception as e:
            self.logger.warning(f"Failed to send client info: {e}")

    def do_handshake(self, vip = None,
                     cancel_on_RQIP_err = False, req_compress=False):
        """Receive vIP and vnet config and request if needed"""
        # AIP/HSK are sent uncompressed by the server (raw struct.pack in
        # on_connect). Read them without zlib decompression to avoid touching
        # the module-level compression state, which could race with other
        # concurrent connections in the same process.
        pkt = recv_packet_raw(self.sock)
        if pkt is None or pkt.type != AIP:
            raise HandshakeError("failed to assign virtual IP")
        self.vip_int = int.from_bytes(pkt.payload, 'big')
        self.logger.info(f"[vnet] Virtual IP: {int_to_ip(self.vip_int)}")
        pkt = recv_packet_raw(self.sock)
        if pkt is None or pkt.type != HSK:
            raise HandshakeError("failed to receive handshake config")
        # Parse the server-supplied config safely (ast.literal_eval, not eval).
        compression_byte, self.config = _parse_handshake_config(pkt.payload)
        enable_compression = compression_byte == 1
        version = self.config[0]
        server_token = self.config[1]
        self.logger.info(f"[vnet] vnet version: {version}")
        self.logger.info(f"[vnet] vnet server token: {server_token}")
        self.logger.info(f"[vnet] Compression status: {compression_byte}")
        if enable_compression:
            self.compression = CompressionState(enabled=True)
        if req_compress and not enable_compression:
            self.logger.error(f"[vnet] Compression required, but not enabled on the server. Dropping conn")
            self.close("Compression required")
            return

        if not vip: return

        try:
            pkt = Packet(RQIP, payload=ip_to_int(vip).to_bytes(4, 'big'))
            self._send_all(pkt.to_bytes(self.compression))
            # Wait for response
            pkt = Packet.from_socket(self.sock, raise_on_error=True, compression=self.compression)
            if pkt.type != RQIP:
                raise HandshakeError("failed to request IP")
            response = pkt.payload.decode()
            print(response)
            if "E:" in response:
                raise HandshakeError("failed to handshake - {}".format(response.replace("E:", "")), response.replace("E:", ""))
            if "D:" in response:
                self.logger.debug(f"[vnet] Successfully requested ip: {response}")
                additional_msg = response.replace("D:", " with msg: ")
                if additional_msg == " with msg:":
                    additional_msg = ""
                pkt = Packet.from_socket(self.sock, raise_on_error=True, compression=self.compression)
                self.vip_int = ip_to_int(pkt.payload.decode())
                self.logger.info(f"[vnet] Requested IP: {int_to_ip(self.vip_int)}" + additional_msg)
        except HandshakeError as e:
            self.logger.error("Error while requesting vIP: " + str(e.core_error))
            if cancel_on_RQIP_err:
                self.logger.warning("Handshake failed, exiting...")
                self.close()
                exit(-1)
            return

    def do_c2c_handshake(self, c2c_vip: str | int | None = None, use_dh: bool = True):
        """
        Make client to client encrypted connection.

        Only the Diffie-Hellman (X25519) key exchange is supported. The old
        plaintext key-exchange handshake has been removed because the server
        (and anyone observing routed traffic) could recover the session key.

        :param c2c_vip: Target client virtual IP
        :param use_dh: retained for API compatibility; must be True.
        :raises HandshakeError: if ``use_dh`` is False or the VIP is missing.
        """
        if not self.running: return
        c2c_vip = ip_to_int(c2c_vip) if isinstance(c2c_vip, str) else c2c_vip

        if not c2c_vip:
            raise HandshakeError("c2c virtual ip not provided")

        if not use_dh:
            raise HandshakeError(
                "legacy C2C handshake has been removed; use_dh=True (DH) is required"
            )
        self._do_dh_c2c_handshake(c2c_vip)

    def _do_dh_c2c_handshake(self, c2c_vip: int):
        """
        Diffie-Hellman based C2C handshake (SECURE - recommended).
        Uses X25519 elliptic curve for key exchange.
        Even if the server sees all traffic, it cannot derive the shared secret.
        """
        self.logger.info(f"[vnet] Starting DH-based C2C handshake with {int_to_ip(c2c_vip)}")
        
        # 1. Generate ephemeral key pair
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # 2. Add session metadata (timestamp for freshness)
        timestamp = int(time.time()).to_bytes(8, 'big')
        session_id = os.urandom(8)
        
        # 3. Send our public key: [HC2C(1)] + [session_id(8)] + [timestamp(8)] + [public_key(32)]
        handshake_payload = bytes([HC2C]) + session_id + timestamp + public_bytes
        pkt = Packet(S2C, handshake_payload, src_ip=self.vip_int, dst_ip=c2c_vip)
        self._send_all(pkt.to_bytes(self.compression))
        
        self.logger.debug(f"[vnet] Sent DH public key to {int_to_ip(c2c_vip)}")
        
        # 4. Wait for their public key or an HC2C error via the receive loop
        queue: Queue = Queue(maxsize=1)
        self._pending_c2c_responses[c2c_vip] = queue
        try:
            pkt = queue.get(timeout=30)
        except Empty:
            raise HandshakeError("DH C2C handshake timed out")
        finally:
            self._pending_c2c_responses.pop(c2c_vip, None)
        
        if pkt.type not in encryptedTypes or len(pkt.payload) < 1 or pkt.payload[0] != HC2C:
            raise HandshakeError("Failed DH c2c handshake: invalid response")
        
        # Check for HC2C error frame: [HC2C, 0xFF, reason]
        if len(pkt.payload) >= 2 and pkt.payload[1] == 0xFF:
            reason = pkt.payload[2:].decode(errors='ignore')
            raise HandshakeError(f"Failed DH c2c handshake: {reason}")
        
        # Parse response: [HC2C(1)] + [session_id(8)] + [timestamp(8)] + [public_key(32)]
        if len(pkt.payload) < 49:  # 1 + 8 + 8 + 32
            raise HandshakeError("Failed DH c2c handshake: incomplete response")
        
        recv_session_id = pkt.payload[1:9]
        recv_timestamp = int.from_bytes(pkt.payload[9:17], 'big')
        peer_public_bytes = pkt.payload[17:49]
        
        # Verify session freshness (within 5 minutes)
        current_time = int(time.time())
        if abs(current_time - recv_timestamp) > 300:
            self.logger.warning(f"[vnet] Timestamp mismatch: {current_time - recv_timestamp}s difference")
        
        # 5. Perform Diffie-Hellman exchange
        try:
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
            shared_secret = private_key.exchange(peer_public_key)
        except Exception as e:
            raise HandshakeError(f"Failed DH c2c handshake: invalid public key: {e}")
        
        # 6. Derive session keys using HKDF with session context. The two
        # session IDs are sorted so both peers derive the same context even
        # when they initiate a handshake simultaneously.
        lo, hi = sorted((session_id, recv_session_id))
        context_info = b'dosp-c2c-dh-v1' + lo + hi
        keys = derive_tunnel_keys(shared_secret, info=context_info)
        
        # 7. Create secure tunnel
        tunnel = TunneledClient(
            c2c_vip, 
            logger=self.logger, 
            sock=self.sock,
            use_dh=True,
            compression=self.compression,
            send_lock=self._send_lock,
        )
        tunnel.encryption_key = keys['encryption']
        tunnel.mac_key = keys['mac']
        tunnel.iv_material = keys['iv_material']
        tunnel.encryption_completed = True
        
        self.tunnels[c2c_vip] = tunnel
        
        self.logger.info(f"[vnet] ✓ Secure DH C2C tunnel established with {int_to_ip(c2c_vip)}")
        self.logger.debug(f"[vnet] Session: {session_id.hex()}, Keys derived, MAC enabled")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def send_multi(self, packets: list[Packet], on_error=None, max_chunk_size: int = 0):
        """Send multiple packets bundled as MPAK packet(s).
        If max_chunk_size > 0, automatically splits into chunks where each
        chunk's estimated uncompressed sub-packet payload stays under the limit.
        All sub-packets must be destined for the server (not C2C tunnels).
        """
        if not self.running:
            return

        if max_chunk_size > 0:
            for batch in _split_mpak_batches(packets, max_chunk_size):
                try:
                    self._send_all(Packet.multi(batch).to_bytes(self.compression))
                except Exception as e:
                    self.logger.error(f"[vnet] Error sending MPAK: {e}")
                    if on_error is None:
                        raise PacketError("failed to send MPAK: " + str(e))
                    return
        else:
            try:
                self._send_all(Packet.multi(packets).to_bytes(self.compression))
            except Exception as e:
                self.logger.error(f"[vnet] Error sending MPAK: {e}")
                if on_error is None:
                    raise PacketError("failed to send MPAK: " + str(e))

    def send(self, pkt: Packet, on_error = None):
        if not self.running: return
        pkt.src_ip = self.vip_int
        if pkt.dst_ip in self.tunnels:
            try:
                self.tunnels[pkt.dst_ip].send(pkt)
                return
            except Exception as e:
                self.logger.warning(f"[vnet] C2C tunnel to {int_to_ip(pkt.dst_ip)} failed: {e}; removing tunnel")
                del self.tunnels[pkt.dst_ip]
                # Fall through to send via server (will get ERR if peer is gone)
        try:
            self._send_all(pkt.to_bytes(self.compression))
        except Exception as e:
            self.logger.error(f"[vnet] Error sending packet: {e}")
            if on_error is None:
                raise PacketError("failed to send packet: " + str(e))
            elif on_error == "ignore":
                return

    def receive(self, on_error=None) -> Packet | None:
        """Receive packet from server or C2C tunnel"""
        if not self.check_connection() or not self.running:
            return None
        # Mark that an application receive loop is driving the socket so that
        # admin/response calls route through queues instead of reading directly.
        self._receive_loop_active = True
        try:
            # Drain MPAK sub-packet queue first
            if self._mpak_queue:
                return self._mpak_queue.pop(0)

            pkt = Packet.from_socket(self.sock, compression=self.compression)
            if pkt is None:
                return None

            # Transparently unpack MPAK packets
            if pkt.type == MPAK:
                self._mpak_queue = pkt.unpack()
                if not self._mpak_queue:
                    return None
                pkt = self._mpak_queue.pop(0)

            self.logger.debug(f"Received raw packet: {pkt}")

            # Check if this is a handshake initiation or error from another client
            if pkt.type in encryptedTypes and len(pkt.payload) > 0 and pkt.payload[0] == HC2C:
                # If a handshake thread is waiting for a response from this peer,
                # dispatch the packet there instead of treating it as incoming
                if pkt.src_ip in self._pending_c2c_responses:
                    self._pending_c2c_responses[pkt.src_ip].put(pkt)
                    return None
                # If HC2C error marker present, just log it
                if len(pkt.payload) >= 2 and pkt.payload[1] == 0xFF:
                    reason = pkt.payload[2:].decode(errors='ignore')
                    self.logger.error(f"[vnet] C2C handshake error from {int_to_ip(pkt.src_ip)}: {reason}")
                    return None
                self._handle_incoming_c2c_handshake(pkt)
                return None  # Handshake packets are not returned to application
            
            # Handle UNREACHABLE error - clean up tunnel automatically
            if pkt.type == ERR and len(pkt.payload) >= 5 and pkt.payload[0] == ERR_CODES.UNREACHABLE:
                unreachable_ip = int.from_bytes(pkt.payload[1:5], 'big')
                if unreachable_ip in self.tunnels:
                    del self.tunnels[unreachable_ip]
                    self.logger.warning(f"[vnet] C2C tunnel to {int_to_ip(unreachable_ip)} removed: client unreachable")
                self.logger.warning(f"[vnet] Client {int_to_ip(unreachable_ip)} is unreachable")
                return None

            # If packet is from an established tunnel, decrypt it
            tunnel = self.tunnels.get(pkt.src_ip, None)
            
            if tunnel is not None and pkt.type in encryptedTypes:
                # Heuristic: only attempt decrypt if payload looks like an authenticated frame
                min_auth_len = MAC_SIZE + GCM_NONCE_SIZE + 16  # mac + nonce + tag + min ciphertext(0)
                if len(pkt.payload) >= min_auth_len:
                    try:
                        decrypted_pkt = tunnel.decrypt(pkt)
                        # success: reset short S2C counters for this peer
                        self._reset_short_s2c(pkt.src_ip)
                        self.logger.debug(f"Decrypted C2C packet from {int_to_ip(pkt.src_ip)}")
                        pkt = decrypted_pkt
                    except Exception as e:
                        self.logger.error(f"Decryption failed from {int_to_ip(pkt.src_ip)}: {e}")
                        return None
                else:
                    # Payload is too short to be an encrypted+MAC frame; likely plaintext
                    self.logger.warning(f"Received short S2C payload from {int_to_ip(pkt.src_ip)} while tunnel exists; treating as plaintext")
                    self._record_short_s2c(pkt.src_ip)
                    return pkt

            # Route admin/response packets to registered handlers (avoids race with receive loop)
            if pkt.type in self._response_queues:
                try:
                    self._response_queues[pkt.type].put(pkt)
                except Exception:
                    pass
                return None

            return pkt

        except Exception as e:
            self.logger.error(f"[vnet] Error receiving packet: {e}")
            if on_error is None and self.running:
                raise PacketError("failed to receive packet: " + str(e))
            elif on_error == "ignore" or on_error == "i":
                pass
            else:
                self.logger.error(f"[vnet] Unknown 'on_error' value: {on_error}")
                raise PacketError("failed to receive packet: " + str(e))
            return None
    
    def _send_hc2c_error(self, dst_ip: int, reason: str):
        """Send HC2C error frame to a peer via server routing.
        Format: [HC2C(1)] [0xFF] [utf8 reason]
        """
        try:
            payload = bytes([HC2C]) + bytes([0xFF]) + reason.encode()
            pkt = Packet(S2C, payload, src_ip=self.vip_int, dst_ip=dst_ip)
            self._send_all(pkt.to_bytes(self.compression))
        except Exception as e:
            self.logger.debug(f"Failed to send HC2C error to {int_to_ip(dst_ip)}: {e}")

    def _record_short_s2c(self, src_ip: int):
        now = time.time()
        dq = self._short_s2c.get(src_ip)
        if dq is None:
            dq = deque()
            self._short_s2c[src_ip] = dq
        # append and prune older than window
        dq.append(now)
        window = self._short_s2c_window
        while dq and now - dq[0] > window:
            dq.popleft()
        # Check threshold
        if len(dq) >= self._short_s2c_threshold:
            last = self._short_s2c_last_alert.get(src_ip, 0.0)
            if now - last >= self._short_s2c_cooldown:
                self._short_s2c_last_alert[src_ip] = now
                ip_str = int_to_ip(src_ip)
                self.logger.error(f"[vnet] Repeated plaintext frames from {ip_str} while tunnel exists (>= {self._short_s2c_threshold} in {int(self._short_s2c_window)}s). Suggest re-handshake.")
                # Notify peer so it can reset handshake if needed
                self._send_hc2c_error(src_ip, "Peer expects encrypted frames; please re-establish tunnel")

    def _reset_short_s2c(self, src_ip: int):
        self._short_s2c.pop(src_ip, None)
        self._short_s2c_last_alert.pop(src_ip, None)

    def _handle_incoming_c2c_handshake(self, pkt: Packet):
        """Handle incoming C2C handshake from another client"""
        if pkt.src_ip in self.tunnels:
            self.logger.warning(f"C2C tunnel with {int_to_ip(pkt.src_ip)} already exists")
            # Notify initiator that tunnel already exists
            self._send_hc2c_error(pkt.src_ip, "C2C tunnel already exists")
            return
        
        # Detect handshake type by payload length
        payload = pkt.payload[1:]  # Skip HC2C marker
        
        if len(payload) >= 48:  # DH handshake: session_id(8) + timestamp(8) + public_key(32) = 48
            self._respond_dh_handshake(pkt, payload)
        elif len(payload) == 16:  # Legacy (plaintext key) handshake: rejected
            self.logger.warning(f"[vnet] Rejecting legacy C2C handshake from {int_to_ip(pkt.src_ip)} (unsupported)")
            self._send_hc2c_error(pkt.src_ip, "Legacy C2C handshake removed; use DH")
        else:
            self.logger.error(f"Unknown handshake format from {int_to_ip(pkt.src_ip)}, length={len(payload)}")
            self._send_hc2c_error(pkt.src_ip, f"Unknown handshake format (len={len(payload)})")

    def _respond_dh_handshake(self, pkt: Packet, payload: bytes):
        """Respond to Diffie-Hellman handshake request"""
        self.logger.info(f"[vnet] Responding to DH C2C handshake from {int_to_ip(pkt.src_ip)}")
        
        try:
            # Parse incoming handshake
            if len(payload) < 48:
                raise HandshakeError("invalid DH handshake length")
            session_id = payload[:8]
            timestamp = int.from_bytes(payload[8:16], 'big')
            peer_public_bytes = payload[16:48]
            
            # Verify timestamp freshness
            current_time = int(time.time())
            if abs(current_time - timestamp) > 300:
                self.logger.warning(f"[vnet] Old handshake timestamp: {current_time - timestamp}s")
            
            # Generate our key pair
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()
            our_public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            # Compute shared secret
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
            shared_secret = private_key.exchange(peer_public_key)
            
            # Generate our session ID
            our_session_id = os.urandom(8)
            our_timestamp = int(time.time()).to_bytes(8, 'big')
            
            # Send response
            response_payload = bytes([HC2C]) + our_session_id + our_timestamp + our_public_bytes
            response_pkt = Packet(S2C, response_payload, src_ip=self.vip_int, dst_ip=pkt.src_ip)
            self._send_all(response_pkt.to_bytes(self.compression))
            
            # Derive keys (sorted session IDs make the context order-independent)
            lo, hi = sorted((session_id, our_session_id))
            context_info = b'dosp-c2c-dh-v1' + lo + hi
            keys = derive_tunnel_keys(shared_secret, info=context_info)
            
            # Create tunnel
            tunnel = TunneledClient(
                pkt.src_ip,
                logger=self.logger,
                sock=self.sock,
                use_dh=True,
                compression=self.compression,
                send_lock=self._send_lock,
            )
            tunnel.encryption_key = keys['encryption']
            tunnel.mac_key = keys['mac']
            tunnel.iv_material = keys['iv_material']
            tunnel.encryption_completed = True
            
            self.tunnels[pkt.src_ip] = tunnel
            self.logger.info(f"[vnet] ✓ DH C2C tunnel established (responder) with {int_to_ip(pkt.src_ip)}")
        except Exception as e:
            self.logger.error(f"[vnet] Failed to respond to DH handshake from {int_to_ip(pkt.src_ip)}: {e}")
            # notify initiator about failure
            self._send_hc2c_error(pkt.src_ip, f"Responder handshake failure: {e}")

    def check_connection(self):
        if not self.sock:
            self.logger.warning("vnet connection not established")
            return False
        # A WebSocket frame is not a valid liveness probe (an empty send would
        # emit a zero-length frame); consult the transport's closed flag.
        if isinstance(self.sock, WebSocketTransport):
            return not self.sock.closed
        try:
            self.sock.sendall(b"")
            return True
        except Exception:
            return False

    def get_client_hash(self) -> str:
        """Return the auto-generated client hash (read-only)."""
        return self._client_hash

    def _receive_response(self, type_: int, timeout: float = 10) -> Packet | None:
        """Wait for a response packet of the given type.

        If an application receive loop is driving ``receive()``, the matching
        packet is delivered through a per-type queue by that loop. Otherwise
        (e.g. the admin CLI, which has no loop) we read the socket directly so
        we don't sit idle for the whole timeout.
        """
        if not self._receive_loop_active:
            return Packet.from_socket(self.sock, compression=self.compression)
        q: Queue = Queue(maxsize=1)
        self._response_queues[type_] = q
        try:
            return q.get(timeout=timeout)
        except Empty:
            return None
        finally:
            self._response_queues.pop(type_, None)

    def authenticate_admin(self, token: str) -> bool:
        """Authenticate as server admin using an admin token.
        Returns True if server confirms admin privileges.
        """
        if not self.running:
            return False
        try:
            pkt = Packet(AUTH, token.encode())
            self._send_all(pkt.to_bytes(self.compression))
            resp = self._receive_response(AUTH, timeout=10)
            if resp and resp.payload == b"OK":
                self.logger.info("[admin] Authenticated as admin")
                return True
            reason = resp.payload.decode(errors='ignore') if resp else "no response"
            self.logger.warning(f"[admin] Auth failed: {reason}")
            return False
        except Exception as e:
            self.logger.error(f"[admin] Auth error: {e}")
            return False

    def broadcast(self, message: str) -> str | None:
        """Send a broadcast message as admin. Requires prior admin auth.
        Returns server response text or None on failure.
        """
        if not self.running:
            return None
        try:
            pkt = Packet(BCST, message.encode())
            self._send_all(pkt.to_bytes(self.compression))
            resp = self._receive_response(BCST, timeout=10)
            if resp:
                return resp.payload.decode(errors='ignore')
            return None
        except Exception as e:
            self.logger.error(f"[admin] Broadcast error: {e}")
            return None

    def admin_command(self, command: str) -> str | None:
        """Send an admin command to the server. Requires prior admin auth.
        Returns server response text or None on failure.
        """
        if not self.running:
            return None
        try:
            pkt = Packet(ADMIN, command.encode())
            self._send_all(pkt.to_bytes(self.compression))
            resp = self._receive_response(ADMIN, timeout=10)
            if resp:
                return resp.payload.decode(errors='ignore')
            return None
        except Exception as e:
            self.logger.error(f"[admin] Command error: {e}")
            return None

    def close(self, reason=""):
        if getattr(self, "_closed", False):
            return
        self._closed = True
        self.logger.info(f"[vnet] closing connection")
        self.running = False
        if reason:
            payload = f"CC,{reason}".encode()
        else:
            payload = b"CC"
        try:
            self._send_all(Packet(EXIT, payload=payload).to_bytes(self.compression))
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.tunnels.clear()

class LocalClient(Client):
    """Client connected through another python process"""

    def __init__(self, server: 'DoSP', vip=None):
        if not (server.running and server.config.allow_local):
            raise HandshakeError("server is not running or allow_local is disabled")

        self.server = server
        self.running = True
        self._closed = False
        self.config = {}
        self.tunnels = {}
        self._send_lock = threading.Lock()
        self._receive_loop_active = False
        self._pending_c2c_responses = {}
        self._response_queues = {}
        self._mpak_queue = []
        self._short_s2c = {}
        self._short_s2c_last_alert = {}
        self._short_s2c_threshold = 10
        self._short_s2c_window = 60.0
        self._short_s2c_cooldown = 60.0
        self._client_hash = get_client_hash()
        self.compression = server.compression

        self.sock = None
        self.vip_int = server.local_connect(self)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        if vip:
            try:
                pkt = Packet(RQIP, ip_to_int(vip).to_bytes(4, 'big'))
                self.server.handle_packet(pkt, None, self.vip_int)
            except Exception as e:
                self.logger.error(f"Failed to request IP: {e}")

    def send_multi(self, packets: list[Packet], on_error=None, max_chunk_size: int = 0):
        """Send multiple packets bundled as MPAK packet(s).
        If max_chunk_size > 0, automatically splits into chunks where each
        chunk's estimated uncompressed sub-packet payload stays under the limit.
        """
        if max_chunk_size > 0:
            for batch in _split_mpak_batches(packets, max_chunk_size):
                mpak = Packet.multi(batch)
                try:
                    self.server.handle_packet(mpak, None, self.vip_int)
                except Exception as e:
                    self.logger.error(f"[vnet] Error sending MPAK: {e}")
                    if on_error is None:
                        raise PacketError("failed to send MPAK: " + str(e))
                    return
        else:
            mpak = Packet.multi(packets)
            try:
                self.server.handle_packet(mpak, None, self.vip_int)
            except Exception as e:
                self.logger.error(f"[vnet] Error sending MPAK: {e}")
                if on_error is None:
                    raise PacketError("failed to send MPAK: " + str(e))

    def send(self, pkt: Packet, on_error=None):
        pkt.src_ip = self.vip_int
        try:
            self.server.handle_packet(pkt, None, self.vip_int)
        except Exception as e:
            self.logger.error(f"[vnet] Error sending packet: {e}")
            if on_error is None:
                raise PacketError("failed to send packet: " + str(e))

    def receive(self, on_error=None) -> Packet | None:
        self._receive_loop_active = True
        # Drain MPAK sub-packet queue first
        if self._mpak_queue:
            return self._mpak_queue.pop(0)
        with self.server.lock:
            rc = self.server.clients.get(self.vip_int)
        if rc is None:
            return None
        pkt = rc.receive()
        if pkt and pkt.type == MPAK:
            self._mpak_queue = pkt.unpack()
            if not self._mpak_queue:
                return None
            return self._mpak_queue.pop(0)
        return pkt

    def close(self, reason=""):
        if getattr(self, "_closed", False):
            return
        self._closed = True
        self.running = False
        with self.server.lock:
            self.server.clients.pop(self.vip_int, None)
        template_parts = self.server.config.ip_template.split('.')
        x_idx = template_parts.index('x')
        ip_num = int(int_to_ip(self.vip_int).split('.')[x_idx])
        self.server.assigned_ids.discard(ip_num)
        self.server.on_disconnect(self.vip_int, code="CC", reason=reason)

    def check_connection(self):
        return self.running
