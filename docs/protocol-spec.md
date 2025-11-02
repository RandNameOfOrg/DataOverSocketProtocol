# DoSP Protocol Specification

## Protocol Version

**Version**: 0.1.2  
**Default Port**: 7744  
**Transport**: TCP

## Message Format

All DoSP messages consist of a header followed by an optional payload:

```
┌──────────┬──────────┬─────────────┬─────────────┐
│   TYPE   │  LENGTH  │   DST_IP    │   PAYLOAD   │
│  (1 byte)│ (4 bytes)│  (4 bytes)  │  (variable) │
└──────────┴──────────┴─────────────┴─────────────┘
```

### Header Fields

- **TYPE** (1 byte): Message type identifier (see Message Types)
- **LENGTH** (4 bytes, big-endian): Length of the payload section, including DST_IP if present
- **DST_IP** (4 bytes, optional): Destination virtual IP address (only for S2C messages)
- **PAYLOAD** (variable): Message content

## Message Types

### Client Messages (0x01-0x0F)

| Type | Hex  | Name  | Description | Requires DST_IP |
|------|------|-------|-------------|-----------------|
| MSG  | 0x01 | Message | General message to server | No |
| PING | 0x02 | Ping | Keep-alive/latency check | No |
| S2C  | 0x03 | Send to Client | Route message to another client | Yes |
| GCL  | 0x04 | Get Clients List | Request list of connected clients | No |
| FN   | 0x05 | Function | Execute server-side function | No |
| SD   | 0x06 | Server Data | Peer server advertisement | No |
| RQIP | 0x07 | Request IP | Request specific virtual IP | No |
| GSI  | 0x08 | Get Self Info | Get client's own information | No |

### Server Responses (0x10-0x1F)

| Type | Hex  | Name | Description |
|------|------|------|-------------|
| SA   | 0x10 | Server Answer | Generic server response |
| EXIT | 0x11 | Exit | Server requests client disconnect |
| ERR  | 0x12 | Error | Error message |
| AIP  | 0x13 | Assign IP | Virtual IP assignment |
| HSK  | 0x14 | Handshake | Server configuration data |
| HC2C | 0x15 | Handshake C2C | Client-to-client handshake prefix |

**Note**: Types 0x00-0x1F are reserved for built-in functionality. Types 0x20+ are available for custom extensions.

## Connection Flow

### 1. Initial Connection

```
Client                    Server
  |                         |
  |------- TCP Connect ---->|
  |                         |
  |<-------- AIP ----------|  (Assign IP: 0x13)
  |    (4 bytes: vIP)      |
  |                         |
  |<-------- HSK ----------|  (Handshake: 0x14)
  |   (config data)        |
  |                         |
```

### 2. Optional IP Request

```
Client                    Server
  |                         |
  |------- RQIP ---------->|  (Request IP: 0x07)
  |  (desired IP: 4 bytes) |
  |                         |
  |<------ RQIP ----------|  (Response)
  |  ("D:" or "E:...")    |
  |                         |
  |<------ AIP -----------|  (New IP if successful)
  |    (4 bytes: vIP)     |
  |                         |
```

### 3. Client-to-Client (C2C) Handshake

#### Diffie-Hellman Mode (Recommended)

```
Client A                 Server                 Client B
  |                        |                        |
  |------ S2C: HC2C ------>|                        |
  | session_id(8)          |                        |
  | timestamp(8)           |                        |
  | public_key(32)         |                        |
  |                        |------ S2C: HC2C ------>|
  |                        |  (forwarded)           |
  |                        |                        |
  |                        |<----- S2C: HC2C ------|
  |                        | session_id(8)          |
  |                        | timestamp(8)           |
  |                        | public_key(32)         |
  |<----- S2C: HC2C -------|                        |
  | (forwarded)            |                        |
  |                        |                        |
  [Compute shared secret] |                        | [Compute shared secret]
  [Derive session keys]   |                        | [Derive session keys]
```

**Payload Format**:
```
[HC2C marker (1)] + [session_id (8)] + [timestamp (8)] + [X25519 public key (32)]
```

#### Legacy Mode

```
Client A                 Server                 Client B
  |                        |                        |
  |------ S2C: HC2C ------>|                        |
  |     key1 (16)          |                        |
  |                        |------ S2C: HC2C ------>|
  |                        |  (forwarded)           |
  |                        |                        |
  |                        |<----- S2C: HC2C ------|
  |                        |     key2 (16)          |
  |<----- S2C: HC2C -------|                        |
  | (forwarded)            |                        |
  |                        |                        |
  [Combined key: key1+key2]                        [Combined key: key1+key2]
```

**Payload Format**:
```
[HC2C marker (1)] + [random key (16)]
```

## Encrypted Messages

### C2C Tunnel Format

Once a C2C tunnel is established, messages are encrypted:

```
[TYPE] [LENGTH] [DST_IP] [ENCRYPTED_DATA] [MAC]
```

**Encrypted Data Structure**:
```
Encrypted([sequence (8)] + [original_payload])
```

**MAC Calculation**:
```
HMAC-SHA256(mac_key, sequence_bytes + ciphertext)
```

### Encryption Scheme

- **Algorithm**: AES-GCM
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes)
- **Tag Size**: 128 bits (16 bytes)
- **MAC**: HMAC-SHA256 (32 bytes)

### Key Derivation (HKDF)

```python
# From shared secret (32 bytes from X25519 or combined keys)
key_material = HKDF(
    algorithm=SHA256,
    length=96,
    salt=None,
    info=b'dosp-c2c-dh-v1' + session_id + peer_session_id
)

encryption_key = key_material[0:32]   # For AES-GCM
mac_key = key_material[32:64]         # For HMAC
iv_material = key_material[64:96]     # Reserved
```

## Virtual IP Addressing

### Format

Virtual IPs follow a template pattern:
```
"{a}.{b}.{c}.{x}"
```

Where `{x}` is replaced by auto-incremented values starting from 2.

### Reserved IPs

- `{template}.1` - Server itself
- `0.0.0.0` - Invalid/null address
- `127.0.0.1` - Localhost (usually blocked)

### Examples

```python
# Template: "7.10.0.{x}"
Server:   7.10.0.1
Client 1: 7.10.0.2
Client 2: 7.10.0.3

# Template: "192.168.1.{x}"
Server:   192.168.1.1
Client 1: 192.168.1.2
```

## Peer Federation

### Server Advertisement (SD)

Peer servers exchange routing information:

```
[SD (0x06)] [LENGTH] [PAYLOAD]
```

**Payload Structure**:
```
[version (1)] [entry_count (1)] [entries...]
```

**Entry Format**:
```
[host_len (1)] [host (variable)] [port (2)] 
[template_len (1)] [ip_template (variable)] [hop_count (1)]
```

### Routing

1. **Direct Routes**: Configured peer servers (hop_count = 0)
2. **Learned Routes**: Discovered through advertisements (hop_count > 0)
3. **Loop Prevention**: TTL counter and packet digest tracking
4. **Best Path**: Prefer lowest hop count

## Error Codes

| Code | Hex  | Name | Description |
|------|------|------|-------------|
| FNF  | 0x01 | Function Not Found | Requested function doesn't exist |
| FF   | 0x02 | Function Failed | Function execution failed |
| S2CF | 0x03 | S2C Failed | Client-to-client routing failed |
| RQIPF| 0x04 | RQIP Failed | IP request failed |
| SDF  | 0x05 | SD Failed | Server data exchange failed |
| GCLF | 0x06 | GCL Failed | Get clients list failed |
| AIPF | 0x07 | AIP Failed | IP assignment failed |
| HSKF | 0x08 | HSK Failed | Handshake failed |
| UKNP | 0x09 | Unknown Packet | Unknown packet type |

## Exit Codes

When sending EXIT messages:

| Code | Description |
|------|-------------|
| CC   | Client Closed - Normal disconnect |
| EX   | Process Exit - Application terminating |
| UE   | Unexpected Error - Abnormal disconnect |

## Implementation Notes

### Packet Reception

```python
def recv_exact(sock, size: int) -> bytes | None:
    """Receive exactly `size` bytes from socket"""
    buf = b''
    while len(buf) < size:
        part = sock.recv(size - len(buf))
        if not part:
            return None
        buf += part
    return buf
```

### Packet Class

```python
class Packet:
    def __init__(self, type_, payload, dst_ip=None, src_ip=None):
        self.type = type_
        self.payload = payload
        self.dst_ip = dst_ip
        self.src_ip = src_ip
    
    def to_bytes(self) -> bytes:
        if self.type == S2C:
            # Include DST_IP and SRC_IP
            dst_bytes = struct.pack(">I", self.dst_ip)
            src_bytes = struct.pack(">I", self.src_ip or 0)
            total_payload = dst_bytes + src_bytes + self.payload
            return struct.pack(">BI", self.type, len(total_payload)) + total_payload
        else:
            return struct.pack(">BI", self.type, len(self.payload)) + self.payload
```

## Security Considerations

1. **C2C Encryption**: Always use DH mode for production
2. **Sequence Numbers**: Prevent replay attacks
3. **Message Authentication**: HMAC prevents tampering
4. **Session IDs**: Unique session identification
5. **Timestamp Verification**: Reject old handshakes (>5 minutes)

## Performance Recommendations

- Use connection pooling for peer servers
- Implement message batching for high throughput
- Enable TCP_NODELAY for low latency
- Consider connection keep-alive settings
- Monitor TTL exhaustion in complex topologies

## Future Extensions

Reserved type range 0x20-0xFF for:
- Custom application protocols
- Extended authentication mechanisms
- Quality of Service (QoS) markers
- Multicast/broadcast support
- Stream control messages
