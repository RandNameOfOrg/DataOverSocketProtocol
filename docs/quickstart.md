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
