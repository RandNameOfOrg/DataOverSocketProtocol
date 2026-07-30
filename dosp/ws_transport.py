import logging
import socket
import ssl

from wsproto import WSConnection, ConnectionType
from wsproto.events import (
    AcceptConnection,
    BytesMessage,
    CloseConnection,
    Ping,
    Pong,
    Request,
)

_client_available = False
_client_lib = None
try:
    import simple_websocket as _client_lib
    _client_available = True
except ImportError:
    pass


def ws_available() -> bool:
    return _client_available


def ensure_ws_client():
    if not _client_available:
        raise ImportError(
            "simple-websocket is not installed. "
            "Install it with: pip install simple-websocket"
        )


log = logging.getLogger(__name__)


class WSServerConfig:
    def __init__(
        self,
        port: int = 7745,
        host: str = "0.0.0.0",
        certfile: str | None = None,
        keyfile: str | None = None,
        keyfile_password: str | None = None,
    ):
        self.port = port
        self.host = host
        self.certfile = certfile
        self.keyfile = keyfile
        self.keyfile_password = keyfile_password


class WebSocketTransport:
    def __init__(self, sock: socket.socket, peer_addr=("0.0.0.0", 0)):
        self._sock = sock
        self._peer_addr = peer_addr
        self._buf = b""
        self._closed = False

        if _client_lib and isinstance(sock, _client_lib.Client):
            self._mode = "client"
        else:
            self._mode = "server"
            self._ws = WSConnection(ConnectionType.SERVER)
            self._do_handshake_server()

    def _do_handshake_server(self):
        while True:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("WebSocket handshake failed: connection closed")
            self._ws.receive_data(chunk)
            for event in self._ws.events():
                if isinstance(event, Request):
                    resp = self._ws.send(AcceptConnection())
                    self._sock.sendall(resp)
                    return
                elif isinstance(event, CloseConnection):
                    raise ConnectionError("WebSocket handshake rejected by client")

    def sendall(self, data: bytes):
        if self._closed:
            return
        if self._mode == "client":
            self._sock.send(data)
        else:
            output = self._ws.send(BytesMessage(data))
            self._sock.sendall(output)

    def recv(self, n: int) -> bytes:
        while len(self._buf) < n:
            if self._closed:
                return b""
            try:
                if self._mode == "client":
                    msg = self._sock.receive()
                    if msg is None:
                        self._closed = True
                        return b""
                    if isinstance(msg, str):
                        msg = msg.encode()
                    self._buf += msg
                else:
                    chunk = self._sock.recv(4096)
                    if not chunk:
                        self._closed = True
                        return b""
                    self._ws.receive_data(chunk)
                    for event in self._ws.events():
                        if isinstance(event, BytesMessage):
                            self._buf += event.data
                        elif isinstance(event, CloseConnection):
                            self._closed = True
                            try:
                                self._sock.sendall(
                                    self._ws.send(CloseConnection())
                                )
                            except Exception:
                                pass
                            return b""
                        elif isinstance(event, Ping):
                            try:
                                self._sock.sendall(self._ws.send(Pong()))
                            except Exception:
                                pass
            except Exception:
                self._closed = True
                return b""
        result = self._buf[:n]
        self._buf = self._buf[n:]
        return result

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            if self._mode == "client":
                self._sock.close()
            else:
                try:
                    self._sock.sendall(self._ws.send(CloseConnection()))
                except Exception:
                    pass
                self._sock.close()
        except Exception:
            pass

    def getpeername(self):
        try:
            return self._sock.getpeername()
        except Exception:
            return self._peer_addr

    def settimeout(self, value):
        try:
            self._sock.settimeout(value)
        except Exception:
            pass

    def fileno(self):
        return self._sock.fileno()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def create_ws_client_transport(url: str) -> WebSocketTransport:
    ensure_ws_client()
    ws = _client_lib.Client.connect(url)
    return WebSocketTransport(ws, peer_addr=("0.0.0.0", 0))


def create_ws_server_transport(
    client_sock: socket.socket,
    peer_addr: tuple[str, int],
    ws_server_config: WSServerConfig | None = None,
) -> WebSocketTransport:
    sock = client_sock
    if ws_server_config and ws_server_config.certfile:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(
            ws_server_config.certfile,
            ws_server_config.keyfile,
            ws_server_config.keyfile_password,
        )
        sock = ssl_ctx.wrap_socket(sock, server_side=True)
    return WebSocketTransport(sock, peer_addr=peer_addr)
