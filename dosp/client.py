from .protocol import *
import os, logging, socket, time
from collections import deque

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from .server import DoSP


class Client:
    config: dict = {}
    vip_int: int # Virtual IP
    tunnels: dict[int, TunneledClient] = {}

    logger: logging.Logger
    sock: socket.socket
    running: bool

    def __init__(self, host: str = "127.0.0.1", port: int = 7744, vip = None, fixed_vip = False, client_id: int | None = None):
        """
        Client constructor for DoS Protocol
        :param host: DoSP server host (or host:port)
        :param port: DoSP server port
        :param vip: what vIP will be requested
        :param fixed_vip: close connection if requested vIP can not be assigned
        """
        if ":" in host:
            try:
                host, port = host.split(":")
                port = int(port)
            except ValueError:
                raise ConnectionError("Invalid host: \"{}\"".format(host))
        self.logger = logging.getLogger(__name__)
        # Short S2C protection counters per peer
        self._short_s2c: dict[int, deque] = {}
        self._short_s2c_last_alert: dict[int, float] = {}
        self._short_s2c_threshold = 10   # events
        self._short_s2c_window = 60.0    # seconds
        self._short_s2c_cooldown = 60.0  # seconds
        self.initializate_connection(host, port, vip=vip, fixed_vip=fixed_vip)

        self.logger.level = logging.INFO

    def initializate_connection(self, host: str = "127.0.0.1", port: int = 7744, vip = None, fixed_vip = False):
        self.sock = socket.create_connection((host, port))
        self.do_handshake(vip=vip, cancel_on_RQIP_err=fixed_vip)
        self.running = True

    def do_handshake(self, vip = None, cancel_on_RQIP_err = False):
        """Receive vIP and vnet config and request if needed"""
        pkt = Packet.from_socket(self.sock)
        if pkt.type != AIP:
            raise HandshakeError("failed to assign virtual IP")
        self.vip_int = int.from_bytes(pkt.payload, 'big')
        self.logger.info(f"[vnet] Virtual IP: {int_to_ip(self.vip_int)}")
        pkt = Packet.from_socket(self.sock)
        if pkt.type == HSK:
            self.config = eval(pkt.payload.decode())
            version = self.config[0]
            server_token = self.config[1]
            self.logger.info(f"[vnet] vnet version: {version}")
            self.logger.info(f"[vnet] vnet server token: {server_token}")

        if not vip: return

        try:
            pkt = Packet(RQIP, payload=ip_to_int(vip).to_bytes(4, 'big'))
            self.sock.sendall(pkt.to_bytes())
            # Wait for response
            pkt = Packet.from_socket(self.sock, raise_on_error=True)
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
                pkt = Packet.from_socket(self.sock, raise_on_error=True)
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
        
        :param c2c_vip: Target client virtual IP
        :param use_dh: Use Diffie-Hellman key exchange (recommended). 
                       If False, uses legacy random key exchange (less secure)
        """
        if not self.running: return
        c2c_vip = ip_to_int(c2c_vip) if isinstance(c2c_vip, str) else c2c_vip

        if not c2c_vip:
            raise HandshakeError("c2c_vip not provided")

        if use_dh:
            self._do_dh_c2c_handshake(c2c_vip)
        else:
            self._do_legacy_c2c_handshake(c2c_vip)

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
        self.sock.sendall(pkt.to_bytes())
        
        self.logger.debug(f"[vnet] Sent DH public key to {int_to_ip(c2c_vip)}")
        
        # 4. Wait for their public key or an HC2C error
        pkt = Packet.from_socket(self.sock, raise_on_error=True)
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
        
        # 6. Derive session keys using HKDF with session context
        context_info = b'dosp-c2c-dh-v1' + session_id + recv_session_id
        keys = derive_tunnel_keys(shared_secret, info=context_info)
        
        # 7. Create secure tunnel
        tunnel = TunneledClient(
            c2c_vip, 
            logger=self.logger, 
            sock=self.sock,
            use_dh=True
        )
        tunnel.encryption_key = keys['encryption']
        tunnel.mac_key = keys['mac']
        tunnel.iv_material = keys['iv_material']
        tunnel.encryption_completed = True
        
        self.tunnels[c2c_vip] = tunnel
        
        self.logger.info(f"[vnet] ✓ Secure DH C2C tunnel established with {int_to_ip(c2c_vip)}")
        self.logger.debug(f"[vnet] Session: {session_id.hex()}, Keys derived, MAC enabled")

    def _do_legacy_c2c_handshake(self, c2c_vip: int):
        """
        Legacy C2C handshake (LESS SECURE - for backward compatibility).
        Keys are sent through the server in plaintext - server can intercept!
        Use DH-based handshake instead for production.
        """
        self.logger.warning(f"[vnet] Using LEGACY C2C handshake (not recommended for production)")
        
        # C1(create key) send key -> C2()
        key = os.urandom(16)
        pkt = Packet(S2C, bytes([HC2C]) + key, src_ip=self.vip_int, dst_ip=c2c_vip)
        self.sock.sendall(pkt.to_bytes())

        # Wait for 2nd key part
        pkt = Packet.from_socket(self.sock, raise_on_error=True)
        if pkt.type not in encryptedTypes or len(pkt.payload) < 1 or pkt.payload[0] != HC2C:
            raise HandshakeError("failed to start legacy c2c handshake")
        
        key2 = pkt.payload[1:]
        if len(key2) != 16:
            raise HandshakeError(f"Invalid key length received: {len(key2)}")
        
        # Create tunnel with combined key (will derive proper keys internally)
        shared_secret = key + key2
        tunnel = TunneledClient(
            c2c_vip, 
            logger=self.logger, 
            encryption_key=shared_secret, 
            sock=self.sock,
            use_dh=False
        )
        
        self.tunnels[c2c_vip] = tunnel
        self.logger.info(f"[vnet] Legacy C2C tunnel established with {int_to_ip(c2c_vip)}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.sock.close()

    def send(self, pkt: Packet, on_error = None):
        if not self.running: return
        pkt.src_ip = self.vip_int
        if pkt.dst_ip in self.tunnels:
            self.tunnels[pkt.dst_ip].send(pkt)
            return
        try:
            self.sock.sendall(pkt.to_bytes())
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
        try:
            pkt = Packet.from_socket(self.sock)
            if pkt is None:
                return None

            self.logger.debug(f"Received raw packet: {pkt}")

            # Check if this is a handshake initiation or error from another client
            if pkt.type in encryptedTypes and len(pkt.payload) > 0 and pkt.payload[0] == HC2C:
                # If HC2C error marker present, just log it
                if len(pkt.payload) >= 2 and pkt.payload[1] == 0xFF:
                    reason = pkt.payload[2:].decode(errors='ignore')
                    self.logger.error(f"[vnet] C2C handshake error from {int_to_ip(pkt.src_ip)}: {reason}")
                    return None
                self._handle_incoming_c2c_handshake(pkt)
                return None  # Handshake packets are not returned to application
            
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
                        return decrypted_pkt
                    except Exception as e:
                        self.logger.error(f"Decryption failed from {int_to_ip(pkt.src_ip)}: {e}")
                        return None
                else:
                    # Payload is too short to be an encrypted+MAC frame; likely plaintext
                    self.logger.warning(f"Received short S2C payload from {int_to_ip(pkt.src_ip)} while tunnel exists; treating as plaintext")
                    self._record_short_s2c(pkt.src_ip)
                    return pkt

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
            self.sock.sendall(pkt.to_bytes())
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
        elif len(payload) == 16:  # Legacy handshake: just 16 bytes key
            self._respond_legacy_handshake(pkt, payload)
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
            self.sock.sendall(response_pkt.to_bytes())
            
            # Derive keys
            context_info = b'dosp-c2c-dh-v1' + session_id + our_session_id
            keys = derive_tunnel_keys(shared_secret, info=context_info)
            
            # Create tunnel
            tunnel = TunneledClient(
                pkt.src_ip,
                logger=self.logger,
                sock=self.sock,
                use_dh=True
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

    def _respond_legacy_handshake(self, pkt: Packet, payload: bytes):
        """Respond to legacy handshake request"""
        self.logger.warning(f"[vnet] Responding to LEGACY C2C handshake from {int_to_ip(pkt.src_ip)}")
        
        # Generate our key part
        key2 = os.urandom(16)
        response_pkt = Packet(S2C, bytes([HC2C]) + key2, src_ip=self.vip_int, dst_ip=pkt.src_ip)
        self.sock.sendall(response_pkt.to_bytes())
        
        # Create tunnel
        key1 = payload  # First key part from initiator
        shared_secret = key1 + key2
        tunnel = TunneledClient(
            pkt.src_ip, 
            logger=self.logger, 
            encryption_key=shared_secret, 
            sock=self.sock,
            use_dh=False
        )
        
        self.tunnels[pkt.src_ip] = tunnel
        self.logger.info(f"[vnet] Legacy C2C tunnel established (responder) with {int_to_ip(pkt.src_ip)}")

    def check_connection(self):
        if not self.sock:
            self.logger.warning("vnet connection not established")
            return False
        # TODO: send ping request to check connection, make that parallel (asyncio)

        return True

    def close(self):
        self.logger.info(f"[vnet] closing connection")
        self.running = False
        try:
            self.sock.sendall(Packet(EXIT, payload=b"CC").to_bytes())
        except Exception:
            pass
        self.sock.close()

class LocalClient(Client):
    """Client connected through another python process"""

    def __init__(self, server: DoSP, vip=None):
        if not (server.running and server.config["allow_local"]):
            raise HandshakeError("server is not running or allow_local is disabled")

        self.server = server
        self.vip_int = server.local_connect(self)
        self.logger = logging.getLogger(__name__)
        self.logger.level = logging.INFO

        # Simulate handshake
        if vip:
            try:
                pkt = Packet(RQIP, bytes(ip_to_int(vip)))
                self.server.handle_packet(pkt, None, self.vip_int)
            except Exception as e:
                self.logger.error(f"Failed to request IP: {e}")

    def send(self, pkt: Packet, on_error=None):
        pkt.src_ip = self.vip_int
        try:
            self.server.handle_packet(pkt, None, self.vip_int)
        except Exception as e:
            self.logger.error(f"[vnet] Error sending packet: {e}")
            if on_error is None:
                raise PacketError("failed to send packet: " + str(e))
            elif on_error == "ignore":
                return

    def receive(self, on_error=None) -> Packet | None:
        # Local clients need to implement their own message queue
        # This would require changes to the server to support message queues for local clients
        raise NotImplementedError("Message queue for local clients not implemented yet")
