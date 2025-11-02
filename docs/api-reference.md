# DoSP API Reference

## Module: dosp.protocol

Core protocol definitions, packet handling, and encryption utilities.

### Classes

#### `Packet`

Represents a DoSP protocol message.

**Constructor**:
```python
Packet(type_: int, payload: bytes, dst_ip: int = None, 
       src_ip: int = None, encryption_key = None)
```

**Parameters**:
- `type_`: Message type identifier (e.g., MSG, S2C, PING)
- `payload`: Message content as bytes
- `dst_ip`: Destination virtual IP (required for S2C)
- `src_ip`: Source virtual IP (set by client/server)
- `encryption_key`: Optional encryption key for secure channels

**Methods**:

```python
to_bytes() -> bytes
```
Convert packet to wire format for transmission.

```python
@staticmethod
from_socket(sock, src_ip: int = None, 
            raise_on_error: bool = False,
            encryption_key = None) -> Packet | None
```
Read and parse packet from socket.

**Example**:
```python
from dosp.protocol import Packet, MSG, S2C, ip_to_int

# Simple message
pkt = Packet(MSG, b"Hello Server")

# Client-to-client message
pkt = Packet(S2C, b"Hello Client", dst_ip=ip_to_int("7.10.0.3"))

# Receive packet
pkt = Packet.from_socket(socket_obj)
```

---

#### `RemoteClient`

Represents a client connection to the server.

**Constructor**:
```python
RemoteClient(sock: socket.socket | None, ip: int, 
             logger: logging.Logger,
             allow_local: bool = False,
             encryption_key = None)
```

**Methods**:

```python
send(pkt: Packet) -> None
```
Send packet to client.

```python
recv() -> Packet | None
```
Receive packet from client.

---

#### `TunneledClient`

Encrypted client-to-client tunnel with authentication.

**Constructor**:
```python
TunneledClient(ip: int, logger: logging.Logger,
               encryption_key = None,
               sock: socket.socket | None = None,
               use_dh: bool = False,
               private_key = None)
```

**Parameters**:
- `ip`: Remote client's virtual IP
- `logger`: Logger instance
- `encryption_key`: Shared secret or partial key
- `sock`: Socket for communication
- `use_dh`: Whether Diffie-Hellman was used
- `private_key`: X25519 private key (for DH mode)

**Methods**:

```python
complete_key_exchange(second_key_part: bytes)
```
Complete legacy key exchange (use only for backward compatibility).

```python
send(pkt: Packet) -> None
```
Send authenticated encrypted packet.

```python
recv() -> Packet | None
```
Receive and verify encrypted packet.

```python
decrypt(pkt: Packet) -> Packet
```
Decrypt packet received through server.

**Security Features**:
- AES-GCM encryption
- HMAC-SHA256 authentication
- Sequence number replay protection
- TLS-inspired architecture

**Example**:
```python
# Automatically created by Client.do_c2c_handshake()
tunnel = TunneledClient(
    remote_ip, 
    logger=logger,
    encryption_key=shared_secret,
    sock=socket_obj,
    use_dh=True
)

# Send encrypted message
tunnel.send(Packet(S2C, b"Secret message", dst_ip=remote_ip))
```

---

### Functions

#### Encryption/Decryption

```python
encrypt(data: bytes, key: bytes) -> bytes
```
Encrypt data using AES-GCM.
- **Returns**: `nonce(12) + ciphertext + tag(16)`
- **Key size**: 16, 24, or 32 bytes

```python
decrypt(data: bytes, key: bytes) -> bytes
```
Decrypt AES-GCM encrypted data.
- **Raises**: `ValueError` if decryption fails

```python
derive_tunnel_keys(shared_secret: bytes, 
                   info: bytes = b'dosp-c2c-v1') -> dict
```
Derive session keys from shared secret using HKDF.
- **Returns**: `{'encryption': bytes, 'mac': bytes, 'iv_material': bytes}`

**Example**:
```python
from dosp.protocol import encrypt, decrypt, derive_tunnel_keys

# Encrypt
key = os.urandom(32)
ciphertext = encrypt(b"Secret data", key)

# Decrypt
plaintext = decrypt(ciphertext, key)

# Derive keys
shared_secret = b"..." # From DH exchange
keys = derive_tunnel_keys(shared_secret)
enc_key = keys['encryption']
mac_key = keys['mac']
```

#### Network Utilities

```python
recv_exact(sock, size: int) -> bytes | None
```
Receive exactly `size` bytes from socket.

```python
ip_to_int(ip: str) -> int
```
Convert IP string to integer.

```python
int_to_ip(ip_int: int) -> str
```
Convert integer to IP string.

**Example**:
```python
from dosp.protocol import ip_to_int, int_to_ip

ip_int = ip_to_int("7.10.0.5")  # Returns integer
ip_str = int_to_ip(ip_int)       # Returns "7.10.0.5"
```

---

### Constants

#### Message Types

```python
MSG  = 0x01   # Message
PING = 0x02   # Ping
S2C  = 0x03   # Send to client
GCL  = 0x04   # Get clients list
FN   = 0x05   # Run function
SD   = 0x06   # Server data
RQIP = 0x07   # Request IP
GSI  = 0x08   # Get self-info
SA   = 0x10   # Server answer
EXIT = 0x11   # Exit
ERR  = 0x12   # Error
AIP  = 0x13   # Assign IP
HSK  = 0x14   # Handshake
HC2C = 0x15   # C2C Handshake prefix
```

#### Error Codes

```python
class ERR_CODES:
    FNF   = 0x01  # Function not found
    FF    = 0x02  # Function failed
    S2CF  = 0x03  # S2C failed
    RQIPF = 0x04  # RQIP failed
    SDF   = 0x05  # SD failed
    GCLF  = 0x06  # GCL failed
    AIPF  = 0x07  # Assign IP failed
    HSKF  = 0x08  # Handshake failed
    UKNP  = 0x09  # Unknown packet
```

#### Exit Codes

```python
class ClientExitCodes:
    ClientClosed = b"CC"     # Normal disconnect
    ProcessExit = b"EX"       # Process terminating
    UnexpectedError = b"UE"   # Abnormal disconnect
```

---

## Module: dosp.client

Client implementation for connecting to DoSP servers.

### Classes

#### `Client`

Main client class for DoSP protocol.

**Constructor**:
```python
Client(host: str = "127.0.0.1", port: int = 7744,
       vip = None, fixed_vip: bool = False)
```

**Parameters**:
- `host`: Server hostname or "host:port" format
- `port`: Server port (default: 7744)
- `vip`: Requested virtual IP (optional)
- `fixed_vip`: Disconnect if requested vIP unavailable

**Attributes**:
- `vip_int: int` - Assigned virtual IP as integer
- `sock: socket.socket` - Connection socket
- `running: bool` - Client running status
- `config: dict` - Server configuration
- `tunnels: dict[int, TunneledClient]` - Active C2C tunnels

**Methods**:

```python
send(pkt: Packet, on_error = None) -> None
```
Send packet to server or through C2C tunnel.
- `on_error`: Error handling ("ignore" or None)

```python
receive(on_error = None) -> Packet | None
```
Receive packet from server or tunnel.
- Handles decryption automatically
- Processes incoming C2C handshakes

```python
do_c2c_handshake(c2c_vip: str | int, use_dh: bool = True) -> None
```
Establish encrypted tunnel with another client.
- `c2c_vip`: Target client's virtual IP
- `use_dh`: Use Diffie-Hellman (recommended) vs legacy mode

```python
close() -> None
```
Disconnect from server gracefully.

**Context Manager**:
```python
with Client(host="server.example.com") as client:
    # Use client
    pass
# Automatically closed
```

**Example**:
```python
from dosp.client import Client
from dosp.protocol import Packet, MSG, S2C, int_to_ip

# Connect to server
client = Client(host="127.0.0.1", vip="7.10.0.5")
print(f"Connected: {int_to_ip(client.vip_int)}")

# Send message to server
client.send(Packet(MSG, b"Hello!"))

# Establish C2C tunnel
client.do_c2c_handshake(c2c_vip="7.10.0.3")

# Send encrypted message to peer
client.send(Packet(S2C, b"Secret", dst_ip=ip_to_int("7.10.0.3")))

# Receive messages
while True:
    pkt = client.receive()
    if pkt:
        print(f"Received: {pkt}")
    if pkt and pkt.type == EXIT:
        break

client.close()
```

---

#### `LocalClient`

Client for same-process communication with server.

**Constructor**:
```python
LocalClient(server: DoSP, vip = None)
```

**Parameters**:
- `server`: Running DoSP server instance
- `vip`: Requested virtual IP

**Note**: Server must have `allow_local=True`.

**Example**:
```python
from dosp.server import DoSP
from dosp.client import LocalClient

server = DoSP(allow_local=True)
# Start server in background thread

client = LocalClient(server, vip="7.10.0.10")
```

---

## Module: dosp.server

Server implementation for DoSP protocol.

### Classes

#### `DoSP`

Main server class for DoSP protocol.

**Constructor**:
```python
DoSP(host: str = "0.0.0.0", port: int = 7744,
     ip_template: str = "7.10.0.{x}",
     allow_local: bool = False)
```

**Parameters**:
- `host`: Bind address
- `port`: Listen port
- `ip_template`: Virtual IP template
- `allow_local`: Allow LocalClient connections

**Attributes**:
- `clients: dict[int, RemoteClient]` - Connected clients
- `peers: list[dict]` - Peer servers
- `running: bool` - Server running status
- `config: dict` - Server configuration

**Methods**:

```python
start() -> None
```
Start server and accept connections (blocking).

```python
stop() -> None
```
Stop server and disconnect all clients.

```python
add_peer_server(host: str, port: int, 
                ip_template: str) -> int
```
Add peer server for federation.
- **Returns**: Peer index

```python
handle_packet(pkt: Packet, sock: socket.socket, 
              ip_int: int) -> None
```
Process received packet (override for custom handling).

```python
on_connect(sock: socket.socket, ip_int: int) -> None
```
Called when client connects (override for custom logic).

```python
on_disconnect(ip_int: int) -> None
```
Called when client disconnects (override for custom logic).

```python
on_function(function_name: str, ip_int: int) -> tuple[bool, str]
```
Handle FN packets (override to implement custom functions).

**Example**:
```python
from dosp.server import DoSP

# Basic server
server = DoSP(
    host="0.0.0.0",
    port=7744,
    ip_template="10.0.0.{x}"
)

# Add peer server
server.add_peer_server(
    host="peer.example.com",
    port=7744,
    ip_template="10.1.0.{x}"
)

# Start (blocking)
server.start()
```

**Custom Server**:
```python
class MyServer(DoSP):
    def on_connect(self, sock, ip_int):
        super().on_connect(sock, ip_int)
        print(f"Client connected: {int_to_ip(ip_int)}")
    
    def on_disconnect(self, ip_int):
        print(f"Client disconnected: {int_to_ip(ip_int)}")
        super().on_disconnect(ip_int)
    
    def on_function(self, function_name, ip_int):
        if function_name == "get_time":
            # Return success and data
            return True, str(time.time())
        return False, "Unknown function"

server = MyServer()
server.start()
```

---

### Configuration

#### Server Config Dictionary

```python
config = {
    "host": "0.0.0.0",
    "port": 7744,
    "ip_template": "7.10.0.{x}",
    "allow_local": False,
    "peers": [],  # List of peer configurations
    "remoteServers_limit": 64,  # Max learned routes
    "max_hops": 8,  # Max forwarding hops
    "clients_conf": [0x01, 0x0000]  # Version and token
}
```

## Exceptions

```python
class VNetError(Exception)
```
Base exception for protocol errors.

```python
class PacketError(VNetError)
```
Packet processing errors.

```python
class HandshakeError(VNetError)
```
Connection handshake errors.

**Example**:
```python
from dosp.protocol import HandshakeError

try:
    client = Client(host="invalid-server")
except HandshakeError as e:
    print(f"Connection failed: {e}")
```

## Best Practices

1. **Always use context managers**:
   ```python
   with Client(host="server") as client:
       # Your code
   ```

2. **Use DH for C2C tunnels**:
   ```python
   client.do_c2c_handshake(peer_ip, use_dh=True)
   ```

3. **Handle errors gracefully**:
   ```python
   pkt = client.receive(on_error="ignore")
   ```

4. **Close connections properly**:
   ```python
   client.send(Packet(EXIT, b"CC"))
   client.close()
   ```

5. **Validate IPs before use**:
   ```python
   if ip_int not in client.tunnels:
       client.do_c2c_handshake(ip_int)
   ```

## Thread Safety

- `DoSP.clients` dictionary uses thread locks
- Each peer connection has its own lock
- Client send/receive operations are thread-safe
- Multiple clients can connect to same server simultaneously

## Logging

Configure logging levels:

```python
import logging

logging.basicConfig(level=logging.DEBUG)

# Or per-module
logger = logging.getLogger('dosp.client')
logger.setLevel(logging.INFO)
```
