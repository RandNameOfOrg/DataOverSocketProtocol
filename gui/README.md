# DoSP GUI Client

A modern graphical user interface for the DataOverSocketProtocol (DoSP) client built with CustomTkinter.

![DoSP GUI Client](../docs/images/gui_screenshot.png) *(Screenshot placeholder)*

## Features

- 🔌 **Easy Connection**: Simple connection interface with server address and desired vIP
- 💬 **Real-time Messaging**: Send and receive messages from server and other clients
- 🔐 **Secure C2C Tunnels**: Establish encrypted client-to-client connections with a single click
- 📋 **Client Discovery**: View all connected clients on the network
- 🎨 **Modern UI**: Dark/light theme support with customtkinter
- 📝 **Message History**: Scrollable message and log displays
- ⚡ **Non-blocking**: Asynchronous message handling with threading

## Installation

### Prerequisites

```bash
pip install customtkinter
pip install DoSP
```

Or install from source:

```bash
cd DataOverSocketProtocol
pip install -e .
pip install customtkinter
```

### Required Dependencies

- Python 3.8+
- customtkinter
- DoSP (dosp package)
- pycryptodome
- cryptography

## Usage

### Starting the GUI

```bash
python gui/dosp_client_gui.py
```

Or from Python:

```python
from gui.dosp_client_gui import main
main()
```

### Quick Start

1. **Connect to Server**
   - Enter server address (e.g., `127.0.0.1:7744`)
   - Optionally specify desired virtual IP (e.g., `7.10.0.1`)
   - Click "Connect"

2. **Send Messages**
   - Type message in input box
   - Press Enter or click "Send"
   - Messages go to currently set target (server or specific client)

3. **Set Target**
   - Enter target IP or "server" in target field
   - Click "Set Target"
   - All subsequent messages go to this target

4. **Establish Encrypted Tunnel**
   - Set target to a client IP
   - Click "Establish C2C"
   - Wait for confirmation
   - All messages to this client are now encrypted

5. **View Connected Clients**
   - Click "Get Clients"
   - Client list appears in messages area

## Interface Overview

### Connection Panel
- **Server**: Server address (host:port format)
- **Desired vIP**: Request specific virtual IP (optional)
- **Connect/Disconnect**: Toggle connection
- **Status**: Shows connection status and current vIP

### Target Panel
- **Target**: Set message destination (server or client IP)
- **Set Target**: Apply target selection
- **Establish C2C**: Create encrypted tunnel to target
- **Get Clients**: Request list of connected clients

### Message Display
- Shows all sent and received messages
- Color-coded by message type:
  - 📤 Sent messages
  - 📨 Received messages
  - 🔔 System notifications

### Log Display
- Shows protocol-level events
- Connection status
- Tunnel establishment
- Errors and warnings

### Input Area
- Text entry for messages
- Send button
- Enter key to send

## Features in Detail

### Encrypted C2C Tunnels

The GUI supports DoSP's secure client-to-client tunneling:

1. Uses Diffie-Hellman key exchange (X25519)
2. AES-GCM encryption with HMAC-SHA256 authentication
3. Sequence numbers for replay protection
4. Perfect forward secrecy

Once established, all messages to that client are automatically encrypted and decrypted.

### Message Types

The GUI handles various DoSP message types:

- **MSG**: Regular messages to/from server
- **S2C**: Client-to-client messages (encrypted if tunnel exists)
- **GCL**: Client list responses
- **PING**: Keep-alive messages (auto-responded)
- **ERR**: Error messages from server
- **EXIT**: Server disconnect requests

### Threading Model

- **Main Thread**: GUI updates and user interaction
- **Connection Thread**: Background connection establishment
- **Receiver Thread**: Continuous message reception
- **Tunnel Thread**: Background C2C handshake

All threads are daemon threads that terminate when the app closes.

## Configuration

### Default Settings

```python
# Default server
server = "127.0.0.1:7744"

# Default theme
appearance_mode = "dark"  # or "light"
color_theme = "blue"

# Message buffer
max_messages = 1000  # Configurable in code
```

### Customization

Edit `dosp_client_gui.py` to customize:

```python
# Theme
ctk.set_appearance_mode("light")  # "dark", "light", "system"
ctk.set_default_color_theme("green")  # "blue", "green", "dark-blue"

# Window size
self.geometry("1200x800")

# Font sizes
self.messages_text = ctk.CTkTextbox(..., font=("Consolas", 12))
```

## Troubleshooting

### Connection Issues

**Problem**: Cannot connect to server
- Check server address and port
- Verify server is running
- Check firewall settings

**Problem**: "IP already in use"
- Choose different vIP
- Wait for timeout on server
- Restart server if needed

### Message Issues

**Problem**: Messages not received
- Check connection status
- Verify target IP is correct
- Check if client is still connected (use "Get Clients")

**Problem**: Encrypted messages fail
- Ensure C2C tunnel is established
- Check both clients are still connected
- Re-establish tunnel if needed

### GUI Issues

**Problem**: GUI freezes
- Check log display for errors
- Restart application
- Report issue with logs

**Problem**: Text not updating
- Scroll to bottom of message/log area
- Check if connection is still active

## Advanced Usage

### Running Multiple Clients

```bash
# Terminal 1
python gui/dosp_client_gui.py

# Terminal 2
python gui/dosp_client_gui.py

# Set different vIPs for each client
```

### Testing C2C Encryption

1. Start two GUI clients
2. Connect both to same server
3. Note each client's vIP
4. In Client A: Set target to Client B's vIP
5. In Client A: Click "Establish C2C"
6. Wait for confirmation
7. Send messages - they are now encrypted end-to-end

### Monitoring Protocol

The log display shows protocol-level events:

```
[12:34:56] INFO - Connected to 127.0.0.1:7744
[12:34:56] INFO - [vnet] Virtual IP: 7.10.0.2
[12:34:56] INFO - [vnet] vnet version: 1
[12:35:02] INFO - [vnet] Starting DH-based C2C handshake with 7.10.0.3
[12:35:03] INFO - [vnet] ✓ Secure DH C2C tunnel established with 7.10.0.3
```

## Keyboard Shortcuts

- **Enter**: Send message
- **Ctrl+A**: Select all in input box
- **Ctrl+C**: Copy selected text
- **Ctrl+V**: Paste text

## Security Considerations

1. **C2C Tunnels**: Always use DH mode (default)
2. **Server Trust**: Server cannot decrypt C2C messages
3. **Authentication**: Tunnels include HMAC for integrity
4. **Replay Protection**: Sequence numbers prevent replays

## Known Limitations

- Maximum message size: Limited by protocol (typically 1MB)
- No message persistence (messages lost on disconnect)
- No file transfer support (text only)
- Single target at a time (cannot multicast)

## Development

### Project Structure

```
gui/
├── dosp_client_gui.py    # Main GUI application
└── README.md             # This file
```

### Adding Features

To extend the GUI:

1. Add new buttons/widgets in `create_widgets()`
2. Implement handler methods
3. Update `process_packet()` for new message types
4. Add threading for long operations

### Debugging

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Run with verbose output:

```bash
python -u gui/dosp_client_gui.py
```

## Contributing

Contributions welcome! Areas for improvement:

- File transfer support
- Group chat/multicast
- Message persistence
- Contact list management
- Emoji picker
- Markdown formatting
- Voice message support

## License

MIT License - see main project LICENSE file

## Links

- [DoSP Overview](../docs/overview.md)
- [Protocol Specification](../docs/protocol-spec.md)
- [API Reference](../docs/api-reference.md)
- [Main README](../README.md)

## Support

For issues or questions:
- Open an issue on GitHub
- Check documentation in `docs/`
- Review example code in `example.py`
