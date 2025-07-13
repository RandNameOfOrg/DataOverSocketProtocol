from .protocol import *
import os


class Client:
    config: dict = {}
    vip_int: int # Virtual IP
    tunnels: dict[int, RemoteClient] = {}

    logger: logging.Logger
    sock: socket.socket

    def __init__(self, ip: str = "127.0.0.1", port: int = 7744, vip = None):
        self.sock = socket.create_connection((ip, port))
        self.logger = logging.getLogger(__name__)
        self.do_handshake()

    def do_handshake(self, vip = None, cancel_on_RQIP = False):
        """Receive vIP and vnet config and request if needed"""
        pkt = Packet.from_socket(self.sock)
        print(pkt)
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

        if vip:
            try:
                pkt = Packet(RQIP, bytes(ip_to_int(vip)))
                self.sock.sendall(pkt.to_bytes())
                # Wait for response
                pkt = Packet.from_socket(self.sock, raise_on_error=True)
                if pkt.type != RQIP:
                    raise HandshakeError("failed to request IP")
                self.vip_int = ip_to_int(pkt.payload.decode())
                self.logger.info(f"[vnet] Requested IP: {int_to_ip(self.vip_int)}")
            except HandshakeError as e:
                self.logger.error(e)
                self.sock.close()
                if cancel_on_RQIP:
                    self.logger.warning("Handshake failed, exiting...")
                    exit(-1)
                return

    def do_c2c_handshake(self, c2c_vip: str = None):
        """Make client to client encrypted connection"""
        if not c2c_vip:
            raise HandshakeError("c2c_vip not provided")

        pkt = Packet(S2C, bytes(), dst_ip=ip_to_int(c2c_vip))
        key = os.urandom(32)


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.sock.close()

    def send(self, pkt: Packet, on_error = None):
        try:
            self.sock.sendall(pkt.to_bytes())
        except Exception as e:
            self.logger.error(f"[vnet] Error sending packet: {e}")
            if on_error is None:
                raise PacketError("failed to send packet: " + str(e))
            elif on_error == "ignore":
                return

    def receive(self, on_error = None) -> Packet | None:
        try:
            pkt = Packet.from_socket(self.sock)
        except Exception as e:
            self.logger.error(f"[vnet] Error receiving packet: {e}")
            if on_error is None:
                raise PacketError("failed to receive packet: " + str(e))
            elif on_error == "ignore": pass
            return None
        self.logger.debug("[vnet] Received packet: " + str(pkt))
        return pkt


# class LocalClient(Client):
#     """Client connected through another python process"""
#     def __init__(self, server: DoSP, vip = None):
#         if not (server.running and server.config["allow_local"]):
#             raise HandshakeError("server is not running or allow_local is disabled")
#         server.local_connect()