import logging
import socket
import threading
from vnet.protocol import *
from vnet.iptools import int_to_ip, ip_to_int

class DoSP:
    running  = True
    dev_mode = False
    logger: logging.Logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    BANNED_IPs = [
        ip_to_int("0.0.0.0"),
        ip_to_int("127.0.0.1")
    ]
    config = {
        "host": "0.0.0.0",
        "port": 7744,
        "ip_template": "7.10.0.{x}",
        "allow_local": False,
        "clients_conf": [
            0x01, # Version
            0x0000, # Server token (allows to determine what types after 0x1F is)
        ]
    }

    def __init__(self, host="0.0.0.0", port=7744,
                 ip_template="7.10.0.{x}", allow_local = False):
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

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients: dict[int, RemoteClient] = {}  # ip_int -> ServerClient
        self.lock = threading.Lock()
        self.assigned_ids = set()

        self.allow_local = allow_local
        self.server_ip = ip_to_int(self.ip_template.replace("{x}", "1"))
        self.config = {
            "host": self.host,
            "port": self.port,
            "ip_template": self.ip_template,
            "allow_local": self.allow_local,
            "clients_conf": self.config["clients_conf"],
        }

    def _next_ip(self):
        with self.lock:
            x = 2
            while True:
                if x not in self.assigned_ids:
                    ip_str = self.ip_template.replace("{x}", str(x))
                    ip_int = ip_to_int(ip_str)
                    if ip_int not in self.clients:
                        self.assigned_ids.add(x)
                        return ip_int, x
                x += 1

    def start(self):
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
            try:
                sock.close()
            except Exception:
                pass
            with self.lock:
                self.clients.pop(ip_int, None)
                self.assigned_ids.discard(ip_id)
            self.on_disconnect(ip_int)

    def on_connect(self, sock: socket.socket, ip_int: int):
        self.logger.info(f"Client connected: {int_to_ip(ip_int)}")
        pkt = Packet(AIP, ip_int.to_bytes(4, 'big'))
        try:
            sock.sendall(pkt.to_bytes())
        except Exception as e:
            self.logger.error(f"Failed to send IP to {int_to_ip(ip_int)}: {e}")
        pkt = Packet(HSK, str(self.config["clients_conf"]).encode())
        try:
            sock.sendall(pkt.to_bytes())
        except Exception as e:
            self.logger.error(f"Failed to send config to {int_to_ip(ip_int)}: {e}")

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

    def on_function(self, function_name: str, ip_int: int) -> (bool, str):
        self.logger.info(f"Running function from {int_to_ip(ip_int)}: {function_name}")
        return False, "Not enabled"

    def handle_packet(self, pkt: Packet, sock: socket.socket, ip_int: int):
        if pkt.type == MSG:
            self.logger.info(f"[MSG] {int_to_ip(ip_int)}: {pkt.payload.decode(errors='ignore')}")
        elif pkt.type == S2C:
            dst_ip = pkt.dst_ip
            src_ip = pkt.src_ip or ip_int
            with self.lock:
                dst_sock = self.clients.get(dst_ip)
            if dst_sock:
                try:
                    dst_sock.sock.sendall(Packet(S2C, pkt.payload, dst_ip=dst_ip, src_ip=src_ip).to_bytes())
                except Exception as e:
                    self.logger.error(f"Failed to route to {int_to_ip(dst_ip)}: {e}")
            else:
                self.logger.warning(f"No client with IP {int_to_ip(dst_ip)}")
        elif pkt.type == FN:
            done, msg = self.on_function(pkt.payload.decode(), ip_int)
            if not done:
                self.logger.error(f"Function {pkt.payload.decode()} from {int_to_ip(ip_int)} failed: {msg}")
                sock.sendall(Packet(ERR, msg.encode(), src_ip=self.server_ip).to_bytes())
        elif pkt.type == GCL:
            self.logger.debug(f"[{int_to_ip(ip_int)}] Getting clients list")
            with self.lock:
                for ip_int in self.clients.keys():
                    sock.sendall(Packet(GCL, ip_int.to_bytes(4, 'big')).to_bytes())
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
