# 🚀 DoSP Quick Start Guide

Get started with DataOverSocketProtocol in 5 minutes!

## Installation

```bash
# Install from PyPI
pip install DoSP

# Or install from source
git clone https://github.com/yourusername/DataOverSocketProtocol.git
cd DataOverSocketProtocol
pip install -e .

# For GUI client
pip install customtkinter
```

## 1. Start a Server

**Python Script** (server.py):
```python
from dosp.server import DoSP

server = DoSP(
    host="0.0.0.0",
    port=7744,
    ip_template="7.10.0.{x}"
)

print("Server starting...")
server.start()  # This blocks
```

Run it:
```bash
python server.py
```

**Or use the CLI** (no script needed):
```bash
# Start server on default port
python -m dosp --serve

# Custom host, port, and IP template
python -m dosp --serve --host 0.0.0.0 --port 7744 --ip-template 7.34.43.x

# With peer servers and debug logging
python -m dosp --serve --port 7744 --peers 10.0.0.50:7744:7.10.0.x --debug

# Run in background thread
python -m dosp --serve --detach
```

**CLI arguments**:
| Argument | Default | Description |
|---|---|---|
| `--serve` | — | Start the DoSP server |
| `--host` | `0.0.0.0` | Server bind address |
| `--port` | `7744` | Server port |
| `--ip-template` | `7.10.0.x` | Virtual IP template |
| `--peers` | — | Peer servers (`host:port:template`) |
| `--debug` | — | Enable debug logging |
| `--detach` | — | Run server in background thread |
| `--client` | — | Interactive client mode |
| `--admin` | — | Connect as admin (opens admin CLI) |
| `--admin-exec CMD` | — | Execute admin command and exit |
| `--token TOKEN` | — | Admin auth token |
| `--vip` | — | Request a specific vIP in client mode |
| `--config` | — | Path to YAML config file |

**Config file support** (precedence: CLI > env vars > config file > defaults):

Use a `dosp.yaml` (auto-detected) or a custom path with `--config`:
```yaml
# dosp.yaml
serve: true
port: 7744
ip_template: 7.34.43.x
debug: true
peers:
  - 10.0.0.50:7744:7.10.0.x
```

Or `.env` file for environment variables:
```bash
DOSP_PORT=7744
DOSP_IP_TEMPLATE=7.34.43.x
DOSP_DEBUG=true
```

YAML config requires `pyyaml` (`pip install DoSP[yaml]` or `pip install pyyaml`).

## 2. Connect with GUI Client

**Start GUI**:
```bash
python gui/dosp_client_gui.py
```

**Steps**:
1. Enter server: `127.0.0.1:7744`
2. Click "Connect"
3. Start chatting!

## 3. Connect with Python Client

**Python Script** (client.py):
```python
from dosp.client import Client
from dosp.protocol import Packet, MSG, S2C, int_to_ip

# Connect
with Client(host="127.0.0.1:7744") as client:
    print(f"Connected! My vIP: {int_to_ip(client.vip_int)}")
    
    # Send to server
    client.send(Packet(MSG, b"Hello Server!"))
    
    # Receive messages
    while True:
        pkt = client.receive()
        if pkt:
            print(f"Received: {pkt.payload.decode()}")
```

Run it:
```bash
python client.py
```

### Admin CLI

```bash
# Interactive admin shell
python -m dosp --admin --host 127.0.0.1 --port 7744 --token <token>

# Single command
python -m dosp --admin-exec "clients" --host 127.0.0.1 --port 7744 --token <token>
```

Admin CLI arguments (also available via `dosp-admin` command):
| Argument | Description |
|---|---|
| `--token` | Admin auth token |
| `--login USER PASS` | Generate token from username:password |
| `--exec CMD` | Execute one command and exit |
| `--token-file PATH` | Read token from file (default: `dosp_admin.token`) |

## 4. Send Client-to-Client Messages

**Client A**:
```python
from dosp.client import Client
from dosp.protocol import Packet, S2C, ip_to_int

with Client(host="127.0.0.1:7744") as client_a:
    # Send to Client B at 7.10.0.3
    client_a.send(Packet(
        S2C,
        b"Hello from Client A!",
        dst_ip=ip_to_int("7.10.0.3")
    ))
```

**Client B**:
```python
from dosp.client import Client

with Client(host="127.0.0.1:7744", vip="7.10.0.3") as client_b:
    # Receive messages
    while True:
        pkt = client_b.receive()
        if pkt:
            print(f"Received: {pkt.payload.decode()}")
```

## 5. Establish Encrypted Tunnel

**Client A**:
```python
from dosp.client import Client
from dosp.protocol import Packet, S2C, ip_to_int

with Client(host="127.0.0.1:7744") as client_a:
    # Establish encrypted tunnel
    client_a.do_c2c_handshake(c2c_vip="7.10.0.3", use_dh=True)
    print("Tunnel established!")
    
    # Send encrypted message
    client_a.send(Packet(
        S2C,
        b"Secret message!",
        dst_ip=ip_to_int("7.10.0.3")
    ))
```

**Client B**:
```python
from dosp.client import Client

with Client(host="127.0.0.1:7744", vip="7.10.0.3") as client_b:
    while True:
        pkt = client_b.receive()
        if pkt:
            # Automatically decrypted!
            print(f"Decrypted: {pkt.payload.decode()}")
```

## 6. Using Interactive Messager

**Terminal Client**:
```bash
python interactive_messager.py
```

**Or use the built-in CLI client**:
```bash
# Connect to default server
python -m dosp --client

# Custom host, port, and request a specific vIP
python -m dosp --client --host 127.0.0.1 --port 7744 --vip 7.10.0.10

# Commands: /send <vip> <message>, /exit, /quit
```

**Commands**:
```
/help                    # Show commands
/target 7.10.0.3        # Set target
/clients                # List clients
/myip                   # Show your IP
Hello!                  # Send message
/exit                   # Disconnect
```

## Common Use Cases

### Chat Application
```python
from dosp.client import Client
from dosp.protocol import *

with Client(host="chat.example.com:7744") as client:
    # Establish tunnels with friends
    client.do_c2c_handshake(c2c_vip="7.10.0.5")  # Friend 1
    client.do_c2c_handshake(c2c_vip="7.10.0.6")  # Friend 2
    
    # Send encrypted messages
    client.send(Packet(S2C, b"Hey!", dst_ip=ip_to_int("7.10.0.5")))
```

### Distributed System
```python
from dosp.server import DoSP

# Node 1
server1 = DoSP(ip_template="10.0.0.{x}")
server1.add_peer_server("node2.example.com", 7744, "10.1.0.{x}")
server1.start()

# Node 2
server2 = DoSP(host="0.0.0.0", ip_template="10.1.0.{x}")
server2.add_peer_server("node1.example.com", 7744, "10.0.0.{x}")
server2.start()
```

### Remote Control
```python
class ControlServer(DoSP):
    def on_function(self, func_name, ip_int):
        if func_name == "shutdown":
            # Perform shutdown
            return True, "Shutting down..."
        return False, "Unknown command"

server = ControlServer()
server.start()
```

## GUI Quick Reference

### Connection
1. **Server**: Enter `host:port`
2. **Desired vIP**: Optional specific IP
3. **Connect**: Click to connect

### Messaging
1. **Target**: Set to "server" or client IP
2. **Type message**: In input box
3. **Send**: Press Enter or click Send

### C2C Tunnel
1. **Set target**: Enter client IP
2. **Establish C2C**: Click button
3. **Wait**: For confirmation
4. **Chat**: Messages now encrypted

### Commands
- **Set Target**: Choose message destination
- **Establish C2C**: Create encrypted tunnel
- **Get Clients**: View connected clients

## Troubleshooting

### Server won't start
```bash
# Check if port is in use
netstat -an | grep 7744

# Use different port
server = DoSP(port=7745)
```

### Client can't connect
```python
# Check server address
client = Client(host="127.0.0.1:7744")  # Correct format

# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Messages not received
```python
# Check target IP
from dosp.protocol import ip_to_int
target = ip_to_int("7.10.0.3")  # Validate IP format

# Request client list
client.send(Packet(GCL, b"request"))
```

### Tunnel fails
```python
# Ensure both clients connected
# Use DH mode (recommended)
client.do_c2c_handshake(c2c_vip="7.10.0.3", use_dh=True)

# Check logs for errors
```

## 7. Server Administration

Administer your running DoSP server remotely via the admin CLI tool.

### Token / Account Generation

**Via login** (username + password → token):
```bash
dosp-admin --host 127.0.0.1 --port 7744 --login admin changeme
```
The CLI generates the token locally: `sha256("admin:changeme")`.

**Via pre-generated token**:
```bash
# Generate a token programmatically
python -c "from dosp import generate_admin_token; print(generate_admin_token('admin', 'changeme'))"

# Use it
dosp-admin --host 127.0.0.1 --port 7744 --token <hex-token>
```

**Auto-generated token** (no config needed):
When no `admin_tokens` are configured in `ServerConfig`, the server prints a random token to console on startup:
```
INFO - dosp.server.base - Auto-generated admin token: a1b2c3d4e5f6...
```
For headless servers, set `admin_token_file` to auto-write the token:
```python
ServerConfig(admin_token_file="dosp_admin.token")
```

### Starting a Server with Admin

```python
from dosp.server import DoSP, ServerConfig
from dosp.protocol import generate_admin_token

config = ServerConfig(
    host="0.0.0.0",
    port=7744,
    admin_tokens=[generate_admin_token("admin", "changeme")],
    # Optional: whitelist-only mode
    whitelist_hashes=["<known-client-hash>"],
    hash_whitelist_enabled=False,
)

server = DoSP(config)
server.start()
```

### Admin Commands

| Command | Description |
|---|---|
| `help` | List all commands |
| `clients` | List connected clients with hash, uptime, packet counts |
| `client <vip>` | Show detailed info for a specific client |
| `kick <vip>` | Disconnect a client |
| `ban <vip>` | Ban a client by its hardware hash |
| `unban <hash>` | Remove a hash from the ban list |
| `whitelist <hash>` | Add a hash to the whitelist |
| `whitelist-remove <hash>` | Remove a hash from the whitelist |
| `whitelist-on` | Enable whitelist-only mode (blocks non-whitelisted) |
| `whitelist-off` | Disable whitelist-only mode |
| `block <vip>` | Block a VIP address |
| `unblock <vip>` | Unblock a VIP address |
| `stats` | Show server and per-client packet statistics |
| `broadcast <message>` | Send a message to all connected clients |
| `exit` | Disconnect admin session |

### Client Identity Hash

Every `Client` auto-generates a stable hash from system hardware on connect. The server uses this for ban/whitelist. It cannot be set or overridden without modifying source code.

```python
from dosp import Client

client = Client(host="127.0.0.1")
print(client.get_client_hash())  # e.g. "69120ed21fa0d65b..."
```

## Next Steps

- 📖 Read [Overview](overview.md) for detailed features
- 🔧 Check [API Reference](api-reference.md) for all methods
- 🔐 Review [Protocol Spec](protocol-spec.md) for technical details
- 🖥️ Explore [GUI README](../gui/README.md) for GUI features
- 💡 See [example.py](../examples/example.py) for more examples

## Tips

1. **Always use context managers**:
   ```python
   with Client(...) as client:
       # Your code
   ```

2. **Use DH for security**:
   ```python
   client.do_c2c_handshake(vip, use_dh=True)  # Recommended
   ```

3. **Handle errors gracefully**:
   ```python
   pkt = client.receive(on_error="ignore")
   ```

4. **Check connection before sending**:
   ```python
   if client.running:
       client.send(packet)
   ```

5. **Use threading for real-time apps**:
   ```python
   import threading
   threading.Thread(target=receive_loop, daemon=True).start()
   ```

## Resources

- **Documentation**: `docs/` folder
- **Examples**: `example.py`, `interactive_messager.py`
- **GUI**: `gui/dosp_client_gui.py`
- **Tests**: `tests/` folder

## Getting Help

1. Check documentation in `docs/`
2. Review examples in project root
3. Enable debug logging
4. Check GitHub issues
5. Read protocol specification

---

**Happy Coding! 🎉**

For detailed information, see the full documentation in the `docs/` folder.
