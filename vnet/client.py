from .protocol import *
import os, logging, socket

from .server import DoSP


class Client:
    config: dict = {}
    vip_int: int # Virtual IP
    tunnels: dict[int, TunneledClient] = {}

    logger: logging.Logger
    sock: socket.socket
    running: bool

    def __init__(self, host: str = "127.0.0.1", port: int = 7744, vip = None, fixed_vip = False):
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
        self.initializate_connection(host, port, vip=vip, fixed_vip=False)

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

    def do_c2c_handshake(self, c2c_vip: str | int | None = None):
        """Make client to client encrypted connection"""
        if not self.running: return
        c2c_vip = ip_to_int(c2c_vip) if isinstance(c2c_vip, str) else c2c_vip

        if not c2c_vip:
            raise HandshakeError("c2c_vip not provided")

        key = os.urandom(16)
        pkt = Packet(S2C, bytes(HC2C) + key, src_ip=self.vip_int, dst_ip=c2c_vip)
        self.sock.sendall(pkt.to_bytes())

        # Wait for 2nd key part
        pkt = Packet.from_socket(self.sock, raise_on_error=True)
        print(pkt, "Second key part")
        if pkt.type not in encryptedTypes and pkt.payload[0] != HC2C:
            raise HandshakeError("failed to start c2c handshake")
        key2 = pkt.payload[1:]
        self.tunnels[c2c_vip] = TunneledClient(c2c_vip, logger=self.logger, encryption_key=key + key2, sock=self.sock)
        self.logger.info(f"[vnet] Client to client connection started with {int_to_ip(c2c_vip)}")

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
        if not self.check_connection() or not self.running:
            return None
        try:
            pkt = Packet.from_socket(self.sock)
            if pkt is None:
                return None

            print(f"Received raw packet: {pkt}")  # Debug print

            # Check if this is a handshake initiation from another client
            if pkt.type in encryptedTypes and len(pkt.payload) > 0 and pkt.payload[0] == HC2C:
                print("Detected HC2C handshake initiation")
                if pkt.src_ip not in self.tunnels:
                    key2 = os.urandom(16)
                    response_pkt = Packet(S2C, bytes([HC2C]) + key2, src_ip=self.vip_int, dst_ip=pkt.src_ip)
                    self.sock.sendall(response_pkt.to_bytes())

                    key = pkt.payload[1:]
                    tunnel = TunneledClient(pkt.src_ip, logger=self.logger, encryption_key=key + key2, sock=self.sock)
                    self.tunnels[pkt.src_ip] = tunnel
                    print(f"Created new tunnel with {int_to_ip(pkt.src_ip)}")

            # If packet is from an established tunnel, decrypt it
            tunnel = self.tunnels.get(pkt.src_ip, None)
            print(f"Tunnel for {int_to_ip(pkt.src_ip)}: {tunnel}")  # Debug print

            if tunnel is not None and pkt.type in encryptedTypes:
                try:
                    decrypted_pkt = tunnel.decrypt(pkt)
                    print(f"Decrypted packet: {decrypted_pkt}")  # Debug print
                    return decrypted_pkt
                except Exception as e:
                    self.logger.error(f"Decryption failed: {e}")
                    return None

            return pkt

        except Exception as e:
            self.logger.error(f"[vnet] Error receiving packet: {e}")
            if on_error is None and self.running:
                raise PacketError("failed to receive packet: " + str(e))
            elif on_error == "ignore" or on_error == "i":
                pass
            else:
                self.logger.error(f"[vnet] Unknown \'on_error\' value: {e}")
                raise PacketError("failed to receive packet: " + str(e))
            return None

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