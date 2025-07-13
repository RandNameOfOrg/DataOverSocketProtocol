import logging
import socket
import threading
from vnet.protocol import *
from vnet.iptools import int_to_ip, ip_to_int

class DoSP:
    running  = True
    dev_mode = False
    logger: logging.Logger = logging.getLogger(__name__)
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
        self.host = host
        self.port = port
        self.ip_template = ip_template
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients: dict[int, RemoteClient] = {}  # ip_int -> ServerClient
        self.lock = threading.Lock()
        self.assigned_ids = set()
        self.allow_local = allow_local
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
        print(f"[vnet] Server listening on {self.host}:{self.port}")
        while self.running:
            try:
                client_sock, addr = self.sock.accept()
                threading.Thread(target=self.handle_client, args=(client_sock,), daemon=True).start()
            except Exception as e:
                print(f"[vnet] Accept error: {e}")

    def stop(self):
        """sends a close packet to all clients and stops the server"""
        self.sock.close()

    def handle_client(self, sock: socket.socket):
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
            print(f"[vnet] Client {int_to_ip(ip_int)} forcibly closed the connection")
        except Exception as e:
            print(f"[vnet] Error with client {int_to_ip(ip_int)}: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
            with self.lock:
                self.clients.pop(ip_int, None)
                self.assigned_ids.discard(ip_id)
            self.on_disconnect(ip_int)

    def on_connect(self, sock: socket.socket, ip_int: int):
        print(f"[vnet] Client connected: {int_to_ip(ip_int)}")
        pkt = Packet(AIP, ip_int.to_bytes(4, 'big'))
        try:
            sock.sendall(pkt.to_bytes())
        except Exception as e:
            print(f"[vnet] Failed to send IP to {int_to_ip(ip_int)}: {e}")
        pkt = Packet(HSK, str(self.config["clients_conf"]).encode())
        try:
            sock.sendall(pkt.to_bytes())
        except Exception as e:
            print(f"[vnet] Failed to send config to {int_to_ip(ip_int)}: {e}")

    def local_connect(self, client):
        raise NotImplementedError("Go away")
        int_ip, int_id = self._next_ip()
        with self.lock:
            self.clients[int_ip] = RemoteClient(client, int_ip, self.logger)



    def on_disconnect(self, ip_int: int):
        print(f"[vnet] Client disconnected: {int_to_ip(ip_int)}")

    def on_function(self, function_name: str, ip_int: int) -> (bool, str):
        print(f"[vnet] Running function from {int_to_ip(ip_int)}: {function_name}")
        return False, "Not enabled"

    def handle_packet(self, pkt: Packet, sock: socket.socket, ip_int: int):
        if pkt.type == MSG:
            print(f"[MSG] {int_to_ip(ip_int)}: {pkt.payload.decode(errors='ignore')}")
        elif pkt.type == S2C:
            dst_ip = pkt.dst_ip
            with self.lock:
                dst_sock = self.clients.get(dst_ip)
            if dst_sock:
                try:
                    dst_sock.sock.sendall(Packet(R4C, pkt.payload).to_bytes())
                except Exception as e:
                    print(f"[vnet] Failed to route to {int_to_ip(dst_ip)}: {e}")
            else:
                print(f"[vnet] No client with IP {int_to_ip(dst_ip)}")
        elif pkt.type == FN:
            done, msg = self.on_function(pkt.payload.decode(), ip_int)
            if not done:
                print(f"[vnet] Function {pkt.payload.decode()} from {int_to_ip(ip_int)} failed: {msg}")
                sock.sendall(Packet(ERR, msg.encode()).to_bytes())
        elif pkt.type == GCL:
            print(f"[LOG]{int_to_ip(ip_int)}] Getting clients list")
            with self.lock:
                for ip_int in self.clients.keys():
                    sock.sendall(Packet(GCL, ip_int.to_bytes(4, 'big')).to_bytes())
        elif pkt.type == RQIP:
            new_ip = int.from_bytes(pkt.payload, 'big')

            print(f"[LOG]{int_to_ip(ip_int)}] Requesting IP {int_to_ip(new_ip)}")
            if new_ip in self.assigned_ids:
                print(f"[vnet] IP {int_to_ip(new_ip)} is already assigned to {int_to_ip(ip_int)}")
                sock.sendall(Packet(ERR, b"IP already in use").to_bytes())

            with self.lock:
                self.assigned_ids.remove(ip_int)
                client_sock = self.clients.pop(ip_int, None)
                self.clients[new_ip] = client_sock
                self.assigned_ids.add(new_ip)

            sock.sendall(Packet(AIP, new_ip.to_bytes(4, 'big')).to_bytes())
            print(f"[LOG]{int_to_ip(ip_int)}] IP {int_to_ip(new_ip)} assigned to {int_to_ip(ip_int)}")
        else:
            print(f"[vnet] Unknown packet type {hex(pkt.type)} from {int_to_ip(ip_int)}")
            sock.sendall(Packet(ERR, ERR_CODES.UKNP[0] + b"Unknown packet type").to_bytes())
