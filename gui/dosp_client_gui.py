"""
DoSP Interactive Message Client - GUI Version
A customtkinter-based graphical client for the DataOverSocketProtocol

Features:
- Connect to DoSP servers
- Send messages to server and other clients
- View connected clients
- Establish encrypted C2C tunnels
- Modern dark/light theme interface
"""

import customtkinter as ctk
from tkinter import scrolledtext, messagebox
import threading
import time
import logging
from datetime import datetime
import sys
import os

# Add parent directory to path to import dosp
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dosp.client import Client
from dosp.protocol import Packet, MSG, S2C, GCL, PING, EXIT, ERR, AIP, HC2C, GSI
from dosp.protocol import int_to_ip, ip_to_int, HandshakeError, PacketError


class DoSPGUIClient(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("DoSP Interactive Client")
        self.geometry("900x700")
        
        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Client state
        self.client: Client | None = None
        self.running = False
        self.target_ip = None
        self.tunnels = set()  # Track established tunnels
        
        # Create GUI
        self.create_widgets()
        
        # Setup logging
        self.setup_logging()
        
        # Protocol on close
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_logging(self):
        """Configure logging to display in GUI"""
        handler = GUILogHandler(self.log_message)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', 
                                     datefmt='%H:%M:%S')
        handler.setFormatter(formatter)
        
        # Add handler to dosp loggers
        logging.getLogger('dosp.client').addHandler(handler)
        logging.getLogger('dosp.protocol').addHandler(handler)
        logging.getLogger('dosp.server').addHandler(handler)
    
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # === Connection Frame ===
        self.conn_frame = ctk.CTkFrame(self)
        self.conn_frame.pack(fill="x", padx=10, pady=10)
        
        # Server input
        ctk.CTkLabel(self.conn_frame, text="Server:").grid(row=0, column=0, padx=5, pady=5)
        self.server_entry = ctk.CTkEntry(self.conn_frame, width=200, 
                                         placeholder_text="127.0.0.1:7744")
        self.server_entry.grid(row=0, column=1, padx=5, pady=5)
        self.server_entry.insert(0, "127.0.0.1:7744")
        
        # VIP input
        ctk.CTkLabel(self.conn_frame, text="Desired vIP:").grid(row=0, column=2, padx=5, pady=5)
        self.vip_entry = ctk.CTkEntry(self.conn_frame, width=120, 
                                      placeholder_text="7.10.0.1")
        self.vip_entry.grid(row=0, column=3, padx=5, pady=5)
        
        # Connect button
        self.connect_btn = ctk.CTkButton(self.conn_frame, text="Connect", 
                                         command=self.toggle_connection, width=100)
        self.connect_btn.grid(row=0, column=4, padx=5, pady=5)
        
        # Status label
        self.status_label = ctk.CTkLabel(self.conn_frame, text="Disconnected", 
                                         text_color="red")
        self.status_label.grid(row=0, column=5, padx=5, pady=5)
        
        # === Target Frame ===
        self.target_frame = ctk.CTkFrame(self)
        self.target_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        ctk.CTkLabel(self.target_frame, text="Target:").grid(row=0, column=0, padx=5, pady=5)
        self.target_entry = ctk.CTkEntry(self.target_frame, width=150, 
                                        placeholder_text="server or 7.10.0.2")
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)
        self.target_entry.insert(0, "server")
        
        ctk.CTkButton(self.target_frame, text="Set Target", 
                     command=self.set_target, width=100).grid(row=0, column=2, padx=5, pady=5)
        
        ctk.CTkButton(self.target_frame, text="Establish C2C", 
                     command=self.establish_tunnel, width=120).grid(row=0, column=3, padx=5, pady=5)
        
        ctk.CTkButton(self.target_frame, text="Get Clients", 
                     command=self.request_clients, width=100).grid(row=0, column=4, padx=5, pady=5)
        
        # === Main Content Frame ===
        self.content_frame = ctk.CTkFrame(self)
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Messages display
        ctk.CTkLabel(self.content_frame, text="Messages:", 
                    font=("Arial", 14, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        self.messages_text = ctk.CTkTextbox(self.content_frame, height=300, 
                                           font=("Consolas", 11))
        self.messages_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Log display
        ctk.CTkLabel(self.content_frame, text="Logs:", 
                    font=("Arial", 14, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        self.log_text = ctk.CTkTextbox(self.content_frame, height=150, 
                                       font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # === Input Frame ===
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.message_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Type your message...", 
                                         height=40, font=("Arial", 12))
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(10, 5), pady=10)
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        
        self.send_btn = ctk.CTkButton(self.input_frame, text="Send", 
                                      command=self.send_message, width=100, height=40)
        self.send_btn.pack(side="right", padx=(5, 10), pady=10)
        
        # Initially disable messaging
        self.message_entry.configure(state="disabled")
        self.send_btn.configure(state="disabled")
    
    def log_message(self, message: str, color: str = None):
        """Add message to log display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}\n"
        
        self.log_text.configure(state="normal")
        if color:
            self.log_text.insert("end", formatted)
            # Note: customtkinter doesn't support text tags, so color is ignored
        else:
            self.log_text.insert("end", formatted)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
    
    def display_message(self, message: str, msg_type: str = "info"):
        """Display received message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if msg_type == "sent":
            formatted = f"[{timestamp}] 📤 YOU → {int_to_ip(self.target_ip) if self.target_ip else 'Server'}: {message}\n"
        elif msg_type == "received":
            formatted = f"[{timestamp}] 📨 {message}\n"
        elif msg_type == "system":
            formatted = f"[{timestamp}] 🔔 {message}\n"
        else:
            formatted = f"[{timestamp}] {message}\n"
        
        self.messages_text.configure(state="normal")
        self.messages_text.insert("end", formatted)
        self.messages_text.see("end")
        self.messages_text.configure(state="disabled")
    
    def toggle_connection(self):
        """Connect or disconnect from server"""
        if self.running:
            self.disconnect()
        else:
            self.connect()
    
    def connect(self):
        """Connect to DoSP server"""
        server = self.server_entry.get().strip()
        vip = self.vip_entry.get().strip() or None
        
        if not server:
            messagebox.showerror("Error", "Please enter server address")
            return
        
        # Parse host:port
        if ":" in server:
            host, port = server.rsplit(":", 1)
            try:
                port = int(port)
            except ValueError:
                messagebox.showerror("Error", "Invalid port number")
                return
        else:
            host = server
            port = 7744
        
        self.log_message(f"Connecting to {host}:{port}...")
        self.connect_btn.configure(state="disabled")
        
        # Connect in background
        threading.Thread(target=self._connect_thread, args=(host, port, vip), daemon=True).start()
    
    def _connect_thread(self, host: str, port: int, vip: str | None):
        """Background connection thread"""
        try:
            self.client = Client(host=f"{host}:{port}", vip=vip, fixed_vip=False)
            self.running = True
            
            # Update GUI
            self.after(0, self._on_connected)
            
            # Start receiver thread
            threading.Thread(target=self.receive_loop, daemon=True).start()
            
        except Exception as e:
            self.after(0, lambda: self._on_connection_failed(str(e)))
    
    def _on_connected(self):
        """Called when connection succeeds"""
        vip_str = int_to_ip(self.client.vip_int)
        self.log_message(f"✅ Connected! Your vIP: {vip_str}", "green")
        self.display_message(f"Connected to server. Your vIP: {vip_str}", "system")
        
        self.status_label.configure(text=f"Connected ({vip_str})", text_color="green")
        self.connect_btn.configure(text="Disconnect", state="normal")
        self.message_entry.configure(state="normal")
        self.send_btn.configure(state="normal")
    
    def _on_connection_failed(self, error: str):
        """Called when connection fails"""
        self.log_message(f"❌ Connection failed: {error}", "red")
        messagebox.showerror("Connection Failed", f"Failed to connect:\n{error}")
        self.connect_btn.configure(state="normal")
    
    def disconnect(self):
        """Disconnect from server"""
        if self.client:
            self.log_message("Disconnecting...")
            self.running = False
            try:
                self.client.close()
            except Exception as e:
                self.log_message(f"Error during disconnect: {e}")
            finally:
                self.client = None
                self.target_ip = None
                self.tunnels.clear()
                
                self.status_label.configure(text="Disconnected", text_color="red")
                self.connect_btn.configure(text="Connect")
                self.message_entry.configure(state="disabled")
                self.send_btn.configure(state="disabled")
                
                self.display_message("Disconnected from server", "system")
    
    def send_message(self):
        """Send message to target"""
        if not self.running or not self.client:
            return
        
        message = self.message_entry.get().strip()
        if not message:
            return
        
        try:
            if self.target_ip:
                # Send to client
                pkt = Packet(S2C, message.encode(), dst_ip=self.target_ip)
                self.client.send(pkt, on_error="ignore")
                self.display_message(message, "sent")
            else:
                # Send to server
                pkt = Packet(MSG, message.encode())
                self.client.send(pkt)
                self.display_message(message, "sent")
            
            self.message_entry.delete(0, "end")
            
        except Exception as e:
            self.log_message(f"Failed to send message: {e}", "red")
            messagebox.showerror("Send Error", str(e))
    
    def set_target(self):
        """Set message target"""
        target = self.target_entry.get().strip().lower()
        
        if target == "server":
            self.target_ip = None
            self.log_message("🎯 Target set: Server")
            self.display_message("Target set to Server", "system")
        else:
            try:
                self.target_ip = ip_to_int(target)
                self.log_message(f"🎯 Target set: {target}")
                self.display_message(f"Target set to {target}", "system")
            except Exception as e:
                messagebox.showerror("Error", f"Invalid IP format: {e}")
    
    def establish_tunnel(self):
        """Establish C2C encrypted tunnel"""
        if not self.running or not self.client:
            messagebox.showwarning("Not Connected", "Please connect to server first")
            return
        
        target = self.target_entry.get().strip()
        if not target or target.lower() == "server":
            messagebox.showwarning("Invalid Target", "Please set a client IP as target")
            return
        
        try:
            target_ip = ip_to_int(target)
            
            if target_ip in self.tunnels:
                self.log_message(f"Tunnel to {target} already exists")
                return
            
            self.log_message(f"Establishing secure tunnel to {target}...")
            self.display_message(f"Establishing secure C2C tunnel to {target}...", "system")
            
            # Run in background
            threading.Thread(target=self._establish_tunnel_thread, 
                           args=(target_ip,), daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse IP: {e}")
    
    def _establish_tunnel_thread(self, target_ip: int):
        """Background tunnel establishment"""
        try:
            self.client.do_c2c_handshake(c2c_vip=target_ip, use_dh=True)
            self.tunnels.add(target_ip)
            
            ip_str = int_to_ip(target_ip)
            self.after(0, lambda: self.log_message(f"✅ Secure tunnel established with {ip_str}"))
            self.after(0, lambda: self.display_message(
                f"Encrypted C2C tunnel established with {ip_str}", "system"))
            
        except Exception as e:
            err_msg = str(e)
            self.after(0, lambda msg=err_msg: self.log_message(f"❌ Tunnel failed: {msg}", "red"))
            self.after(0, lambda msg=err_msg: messagebox.showerror("Tunnel Error", msg))
    
    def request_clients(self):
        """Request list of connected clients"""
        if not self.running or not self.client:
            messagebox.showwarning("Not Connected", "Please connect to server first")
            return
        
        try:
            self.client.send(Packet(GCL, b"request"))
            self.log_message("📋 Requested clients list")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def receive_loop(self):
        """Background thread for receiving messages"""
        while self.running:
            try:
                pkt = self.client.receive(on_error="ignore")
                
                if pkt is None:
                    time.sleep(0.1)
                    continue
                
                self.process_packet(pkt)
                
            except PacketError:
                if self.running:
                    self.after(0, lambda: self.log_message("Connection lost", "red"))
                break
            except Exception as e:
                if self.running:
                    self.after(0, lambda: self.log_message(f"Receive error: {e}", "red"))
                time.sleep(0.5)
        
        # Connection lost
        if self.running:
            self.after(0, self.disconnect)
    
    def process_packet(self, pkt: Packet):
        """Process received packet"""
        if pkt.type == S2C:
            # Message from another client
            sender = int_to_ip(pkt.src_ip) if pkt.src_ip else "Unknown"
            message = pkt.payload.decode(errors='ignore')
            self.after(0, lambda: self.display_message(f"From {sender}: {message}", "received"))
        
        elif pkt.type == MSG:
            # Message from server
            message = pkt.payload.decode(errors='ignore')
            self.after(0, lambda: self.display_message(f"Server: {message}", "received"))
        
        elif pkt.type == GCL:
            # Batched clients list: multiple 4-byte IPs
            data = pkt.payload
            if len(data) % 4 != 0:
                # Fallback: handle legacy single-entry
                try:
                    client_ip = int.from_bytes(data, 'big')
                    ip_str = int_to_ip(client_ip)
                    self.after(0, lambda: self.display_message(f"Client: {ip_str}", "system"))
                except Exception:
                    self.after(0, lambda: self.log_message("Malformed clients list payload", "red"))
            else:
                for i in range(0, len(data), 4):
                    client_ip = int.from_bytes(data[i:i+4], 'big')
                    ip_str = int_to_ip(client_ip)
                    self.after(0, lambda ip_str=ip_str: self.display_message(f"Client: {ip_str}", "system"))
        
        elif pkt.type == ERR:
            # Error message
            error = pkt.payload.decode(errors='ignore')
            self.after(0, lambda: self.log_message(f"Server error: {error}", "red"))
        
        elif pkt.type == EXIT:
            # Server disconnect request
            self.after(0, lambda: self.log_message("Server requested disconnect"))
            self.running = False
        
        elif pkt.type == PING:
            # Respond to ping
            self.client.send(Packet(PING, b"pong"))
    
    def on_closing(self):
        """Handle window close"""
        if self.running:
            self.disconnect()
        self.destroy()


class GUILogHandler(logging.Handler):
    """Custom log handler to display logs in GUI"""
    
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
    
    def emit(self, record):
        msg = self.format(record)
        # Determine color based on level
        color = None
        if record.levelno >= logging.ERROR:
            color = "red"
        elif record.levelno >= logging.WARNING:
            color = "orange"
        
        try:
            self.callback(msg, color)
        except Exception:
            pass


def main():
    """Run the GUI application"""
    app = DoSPGUIClient()
    app.mainloop()


if __name__ == "__main__":
    main()
