# DoSP (Data over Socket Protocol) - Overview

## Introduction

DoSP is a TCP-based protocol designed for routing and forwarding messages between clients through a central server. It operates on port **7744** by default and provides a virtual IP addressing system for clients.

## Key Features

- **Virtual IPv4 Addressing**: Each client receives a unique virtual IP (vIP) in the format `7.10.0.{x}` (configurable)
- **Client-to-Client (C2C) Communication**: Direct encrypted tunnels between clients
- **Peer Server Federation**: Support for distributed server networks with automatic routing
- **End-to-End Encryption**: AES-GCM encryption with HMAC-SHA256 authentication
- **Diffie-Hellman Key Exchange**: Secure X25519 ECDH for C2C tunnels
- **Message Types**: Comprehensive packet types for various operations

## Architecture

### Components

1. **Server** (`dosp.server.DoSP`)
   - Central message router
   - Virtual IP assignment
   - Peer federation management
   - Client connection handling

2. **Client** (`dosp.client.Client`)
   - Connect to DoSP servers
   - Send/receive messages
   - Establish C2C encrypted tunnels
   - Support for both remote and local connections

3. **Protocol** (`dosp.protocol`)
   - Packet encoding/decoding
   - Encryption/decryption utilities
   - Message type definitions
   - Network utilities

### Virtual IP System

The server assigns each client a virtual IP address from a configurable template:

```python
# Default template
ip_template = "7.10.0.{x}"  # Results in: 7.10.0.2, 7.10.0.3, etc.

# Custom templates
ip_template = "10.0.0.{x}"
ip_template = "192.168.1.{x}"
```

## Message Format

All DoSP messages follow this structure:

```
[2B TYPE] [4B LENGTH] [optional 4B DST_IP] [PAYLOAD]
```

- **TYPE** (1 byte): Message type identifier
- **LENGTH** (4 bytes): Total length of payload (and DST_IP if present)
- **DST_IP** (4 bytes): Destination IP for S2C messages
- **PAYLOAD**: Message content

## Security Features

### C2C Encryption

1. **Diffie-Hellman Mode (Recommended)**
   - X25519 elliptic curve key exchange
   - Server cannot decrypt messages
   - Forward secrecy
   - Session-based authentication

2. **Legacy Mode**
   - Random key exchange through server
   - Less secure but backward compatible

### Message Authentication

- HMAC-SHA256 for integrity verification
- Sequence numbers for replay protection
- AES-GCM for authenticated encryption

## Use Cases

- **P2P Messaging**: Secure client-to-client communication
- **Distributed Systems**: Federated server networks
- **Virtual Networks**: Create isolated network segments
- **Command & Control**: Remote system management
- **Chat Applications**: Real-time messaging with encryption

## Getting Started

### Installation

```bash
pip install DoSP
```

Or install from source:

```bash
git clone https://github.com/yourusername/DataOverSocketProtocol.git
cd DataOverSocketProtocol
pip install -e .
```

### Quick Start - Server

```python
from dosp.server import DoSP

server = DoSP(
    host="0.0.0.0",
    port=7744,
    ip_template="7.10.0.{x}"
)
server.start()
```

### Quick Start - Client

```python
from dosp.client import Client
from dosp.protocol import Packet, MSG, int_to_ip

with Client(host="127.0.0.1", port=7744) as client:
    print(f"Connected with vIP: {int_to_ip(client.vip_int)}")
    
    # Send message to server
    client.send(Packet(MSG, b"Hello Server!"))
    
    # Receive messages
    while True:
        pkt = client.receive()
        if pkt:
            print(f"Received: {pkt}")
```

## Project Structure

```
DoSP/
├── dosp/
│   ├── __init__.py
│   ├── client.py          # Client implementation
│   ├── protocol.py        # Protocol definitions
│   ├── iptools.py         # IP utilities
│   └── server/
│       ├── __init__.py
│       └── base.py        # Server implementation
├── docs/                  # Documentation
├── gui/                   # GUI applications
├── tests/                 # Test files
├── README.md
└── pyproject.toml
```

## Performance

- Supports thousands of concurrent clients
- Low latency message routing
- Efficient peer federation
- Thread-safe implementation

## License

MIT License - See LICENSE file for details

## Links

- [Protocol Specification](./protocol-spec.md)
- [API Reference](./api-reference.md)
- GitHub Repository
- Issue Tracker
