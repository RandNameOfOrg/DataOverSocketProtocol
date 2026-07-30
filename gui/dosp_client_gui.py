"""
DoSP Interactive Message Client - GUI Version
A customtkinter-based graphical client for the DataOverSocketProtocol

Features:
- Connect to DoSP servers
- Send messages to server and other clients
- View connected clients in a sidebar
- Establish encrypted C2C tunnels
- Admin authentication and command interface
- Broadcast messages (admin)
- Modern dark/light theme interface
"""

import customtkinter as ctk
from tkinter import messagebox
import threading
import time
import logging
from datetime import datetime
import sys
import os
# Add parent directory to path to import dosp
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dosp.client import Client
from dosp.protocol import Packet, MSG, S2C, GCL, PING, EXIT, ERR, AUTH, ADMIN, BCST
from dosp.iptools import int_to_ip, ip_to_int
from dosp.protocol import HandshakeError, PacketError


class DoSPGUIClient(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configure window
        self.title("DoSP Interactive Client")
        self.geometry("1050x750")
        self.minsize(900, 600)

        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Client state
        self.client: Client | None = None
        self.running = False
        self.target_ip = None
        self.tunnels = set()
        self.is_admin = False
        self.client_list = []

        # Admin sync primitives (thread-safe receive loop integration)
        self._admin_auth_event = threading.Event()
        self._admin_auth_result = False
        self._admin_cmd_event = threading.Event()
        self._admin_cmd_result = None
        self._admin_bcst_event = threading.Event()
        self._admin_bcst_result = None

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

        logging.getLogger('dosp.client').addHandler(handler)
        logging.getLogger('dosp.protocol').addHandler(handler)
        logging.getLogger('dosp.server').addHandler(handler)

    def create_widgets(self):
        """Create all GUI widgets"""

        # === Connection Frame ===
        self.conn_frame = ctk.CTkFrame(self)
        self.conn_frame.pack(fill="x", padx=10, pady=(10, 0))

        # Row 0: Server info
        ctk.CTkLabel(self.conn_frame, text="Server:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.server_entry = ctk.CTkEntry(self.conn_frame, width=180,
                                         placeholder_text="127.0.0.1:7744")
        self.server_entry.grid(row=0, column=1, padx=5, pady=5)
        self.server_entry.insert(0, "127.0.0.1:7744")

        ctk.CTkLabel(self.conn_frame, text="vIP:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.vip_entry = ctk.CTkEntry(self.conn_frame, width=120,
                                      placeholder_text="7.10.0.x")
        self.vip_entry.grid(row=0, column=3, padx=5, pady=5)

        self.connect_btn = ctk.CTkButton(self.conn_frame, text="Connect",
                                         command=self.toggle_connection, width=100)
        self.connect_btn.grid(row=0, column=4, padx=5, pady=5)

        self.status_label = ctk.CTkLabel(self.conn_frame, text="Disconnected",
                                         text_color="red", width=180, anchor="w")
        self.status_label.grid(row=0, column=5, padx=5, pady=5)

        # Row 1: Admin auth
        ctk.CTkLabel(self.conn_frame, text="Token:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.token_entry = ctk.CTkEntry(self.conn_frame, width=250,
                                        placeholder_text="Admin token")
        self.token_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="w")
        self.token_entry.bind("<Return>", lambda e: self.authenticate_admin())

        self.auth_btn = ctk.CTkButton(self.conn_frame, text="Authenticate",
                                      command=self.authenticate_admin, width=100,
                                      state="disabled")
        self.auth_btn.grid(row=1, column=3, padx=5, pady=5)

        self.admin_status = ctk.CTkLabel(self.conn_frame, text="Not authenticated",
                                         text_color="gray", width=180, anchor="w")
        self.admin_status.grid(row=1, column=4, columnspan=2, padx=5, pady=5, sticky="w")

        self.conn_frame.grid_columnconfigure(5, weight=1)

        # === Target Frame ===
        self.target_frame = ctk.CTkFrame(self)
        self.target_frame.pack(fill="x", padx=10, pady=(5, 0))

        ctk.CTkLabel(self.target_frame, text="Target:").grid(row=0, column=0, padx=5, pady=5)
        self.target_entry = ctk.CTkEntry(self.target_frame, width=150,
                                        placeholder_text="server or 7.10.0.2")
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)
        self.target_entry.insert(0, "server")

        ctk.CTkButton(self.target_frame, text="Set Target",
                     command=self.set_target, width=90).grid(row=0, column=2, padx=5, pady=5)

        ctk.CTkButton(self.target_frame, text="Establish C2C",
                     command=self.establish_tunnel, width=110).grid(row=0, column=3, padx=5, pady=5)

        ctk.CTkButton(self.target_frame, text="Get Clients",
                     command=self.request_clients, width=90).grid(row=0, column=4, padx=5, pady=5)

        self.target_frame.grid_columnconfigure(5, weight=1)

        # === Admin Panel (hidden until admin auth) ===
        self.admin_frame = ctk.CTkFrame(self)
        # Not packed initially; shown on admin auth

        # Quick action buttons row
        quick_btns_frame = ctk.CTkFrame(self.admin_frame, fg_color="transparent")
        quick_btns_frame.pack(fill="x", padx=5, pady=(5, 2))

        ctk.CTkLabel(quick_btns_frame, text="Admin:", font=("Arial", 12, "bold")).pack(side="left", padx=(5, 10))
        ctk.CTkButton(quick_btns_frame, text="Clients", width=70,
                      command=lambda: self._exec_admin_cmd("clients")).pack(side="left", padx=2)
        ctk.CTkButton(quick_btns_frame, text="Stats", width=70,
                      command=lambda: self._exec_admin_cmd("stats")).pack(side="left", padx=2)
        ctk.CTkButton(quick_btns_frame, text="Help", width=70,
                      command=lambda: self._exec_admin_cmd("help")).pack(side="left", padx=2)

        # Kick/Ban mini frame
        kick_frame = ctk.CTkFrame(quick_btns_frame, fg_color="transparent")
        kick_frame.pack(side="left", padx=(10, 2))
        self.kick_entry = ctk.CTkEntry(kick_frame, width=90, placeholder_text="vIP to kick")
        self.kick_entry.pack(side="left", padx=2)
        ctk.CTkButton(kick_frame, text="Kick", width=60,
                      command=lambda: self._exec_admin_cmd(f"kick {self.kick_entry.get().strip()}")).pack(side="left", padx=2)

        ban_frame = ctk.CTkFrame(quick_btns_frame, fg_color="transparent")
        ban_frame.pack(side="left", padx=(5, 2))
        self.ban_entry = ctk.CTkEntry(ban_frame, width=90, placeholder_text="vIP to ban")
        self.ban_entry.pack(side="left", padx=2)
        ctk.CTkButton(ban_frame, text="Ban", width=60,
                      command=lambda: self._exec_admin_cmd(f"ban {self.ban_entry.get().strip()}")).pack(side="left", padx=2)

        # Custom command row
        cmd_frame = ctk.CTkFrame(self.admin_frame, fg_color="transparent")
        cmd_frame.pack(fill="x", padx=5, pady=(2, 5))

        ctk.CTkLabel(cmd_frame, text="Command:").pack(side="left", padx=(5, 5))
        self.admin_cmd_entry = ctk.CTkEntry(cmd_frame, placeholder_text="Type admin command...")
        self.admin_cmd_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.admin_cmd_entry.bind("<Return>", lambda e: self._send_admin_cmd())
        ctk.CTkButton(cmd_frame, text="Execute", width=80,
                      command=self._send_admin_cmd).pack(side="right", padx=(0, 5))

        # === Main Content Frame (horizontal split) ===
        self.content_frame = ctk.CTkFrame(self)
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=(5, 0))

        # Left: Messages
        self.msg_frame = ctk.CTkFrame(self.content_frame)
        self.msg_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

        ctk.CTkLabel(self.msg_frame, text="Messages:",
                    font=("Arial", 14, "bold")).pack(anchor="w", padx=10, pady=(5, 2))

        self.messages_text = ctk.CTkTextbox(self.msg_frame, font=("Consolas", 11))
        self.messages_text.pack(fill="both", expand=True, padx=10, pady=(0, 5))

        # Right: Client list sidebar
        self.client_frame = ctk.CTkFrame(self.content_frame, width=200)
        self.client_frame.pack(side="right", fill="y", padx=(5, 0))
        self.client_frame.pack_propagate(False)

        # Client list header
        client_header = ctk.CTkFrame(self.client_frame, fg_color="transparent")
        client_header.pack(fill="x", padx=5, pady=(5, 2))
        ctk.CTkLabel(client_header, text="Connected Clients",
                    font=("Arial", 12, "bold")).pack(side="left")
        ctk.CTkButton(client_header, text="Refresh", width=60, height=24,
                      command=self.request_clients, font=("Arial", 10)).pack(side="right")

        self.clients_listbox = ctk.CTkScrollableFrame(self.client_frame, height=200)
        self.clients_listbox.pack(fill="both", expand=True, padx=5, pady=(0, 5))

        self._client_labels = {}

        # === Log Frame ===
        self.log_frame = ctk.CTkFrame(self)
        self.log_frame.pack(fill="x", padx=10, pady=(5, 0))

        log_header = ctk.CTkFrame(self.log_frame, fg_color="transparent")
        log_header.pack(fill="x", padx=10, pady=(5, 2))
        ctk.CTkLabel(log_header, text="Logs:",
                    font=("Arial", 12, "bold")).pack(side="left")
        self.log_toggle_btn = ctk.CTkButton(log_header, text="Hide", width=50, height=22,
                                           font=("Arial", 10), command=self.toggle_logs)
        self.log_toggle_btn.pack(side="right")

        self.log_text = ctk.CTkTextbox(self.log_frame, height=120, font=("Consolas", 10))
        self.log_text.pack(fill="x", padx=10, pady=(0, 5))

        # === Input Frame ===
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.pack(fill="x", padx=10, pady=(5, 10))

        self.message_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Type your message...",
                                         height=38, font=("Arial", 12))
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(10, 5), pady=8)
        self.message_entry.bind("<Return>", lambda e: self.send_message())

        self.broadcast_btn = ctk.CTkButton(self.input_frame, text="Broadcast",
                                          command=self._send_broadcast, width=90, height=38,
                                          fg_color="#6b3fa0", hover_color="#8b5fc0")
        # hidden until admin

        self.send_btn = ctk.CTkButton(self.input_frame, text="Send",
                                     command=self.send_message, width=90, height=38)
        self.send_btn.pack(side="right", padx=(5, 10), pady=8)

        # Initially disable inputs
        self.message_entry.configure(state="disabled")
        self.send_btn.configure(state="disabled")

    # ── Admin Panel Visibility ──

    def _show_admin_panel(self):
        self.admin_frame.pack(fill="x", padx=10, pady=(5, 0))
        self.broadcast_btn.pack(side="right", padx=(5, 0), pady=8, before=self.send_btn)

    def _hide_admin_panel(self):
        self.admin_frame.pack_forget()
        self.broadcast_btn.pack_forget()

    # ── Log display ──

    def log_message(self, message: str, color: str = None):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}\n"
        self.after(0, lambda: self._insert_log(formatted))

    def _insert_log(self, formatted: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", formatted)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def toggle_logs(self):
        if self.log_text.winfo_ismapped():
            self.log_text.pack_forget()
            self.log_toggle_btn.configure(text="Show")
        else:
            self.log_text.pack(fill="x", padx=10, pady=(0, 5))
            self.log_toggle_btn.configure(text="Hide")

    # ── Message display ──

    def display_message(self, message: str, msg_type: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if msg_type == "sent":
            target = int_to_ip(self.target_ip) if self.target_ip else "Server"
            formatted = f"[{timestamp}] YOU -> {target}: {message}\n"
        elif msg_type == "received":
            formatted = f"[{timestamp}] {message}\n"
        elif msg_type == "system":
            formatted = f"[{timestamp}] {message}\n"
        elif msg_type == "admin":
            formatted = f"[{timestamp}] [ADMIN] {message}\n"
        else:
            formatted = f"[{timestamp}] {message}\n"

        self.messages_text.configure(state="normal")
        self.messages_text.insert("end", formatted)
        self.messages_text.see("end")
        self.messages_text.configure(state="disabled")

    # ── Client list panel ──

    def _update_client_list(self, ips: list[int]):
        self.client_list = ips
        for widget in self.clients_listbox.winfo_children():
            widget.destroy()
        self._client_labels.clear()

        if not ips:
            label = ctk.CTkLabel(self.clients_listbox, text="(no clients)",
                                text_color="gray", font=("Arial", 10))
            label.pack(pady=10)
            return

        # Sort by IP
        for ip_int in sorted(ips):
            ip_str = int_to_ip(ip_int)
            is_self = self.client and ip_int == self.client.vip_int

            row = ctk.CTkFrame(self.clients_listbox, fg_color="transparent")
            row.pack(fill="x", padx=2, pady=1)

            icon = "[YOU]" if is_self else "    "
            text = f"{icon} {ip_str}"
            label = ctk.CTkLabel(row, text=text, anchor="w", font=("Consolas", 11))
            label.pack(side="left", fill="x", expand=True)

            if not is_self:
                label.bind("<Button-1>", lambda e, ip=ip_str: self._select_client(ip))
                label.configure(cursor="hand2")

            self._client_labels[ip_int] = label

    def _select_client(self, ip_str: str):
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, ip_str)
        self.set_target()

    # ── Connection ──

    def toggle_connection(self):
        if self.running:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        server = self.server_entry.get().strip()
        vip = self.vip_entry.get().strip() or None

        if not server:
            messagebox.showerror("Error", "Please enter server address")
            return

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

        threading.Thread(target=self._connect_thread, args=(host, port, vip), daemon=True).start()

    def _connect_thread(self, host: str, port: int, vip: str | None):
        try:
            self.client = Client(host=f"{host}:{port}", vip=vip, fixed_vip=False)
            self.running = True

            self.after(0, self._on_connected)
            threading.Thread(target=self.receive_loop, daemon=True).start()

        except Exception as e:
            error = str(e) or "unknown error"
            self.after(0, lambda: self._on_connection_failed(error))

    def _on_connected(self):
        if not self.client:
            return
        vip_str = int_to_ip(self.client.vip_int)
        self.log_message(f"Connected! Your vIP: {vip_str}", "green")
        self.display_message(f"Connected to server. Your vIP: {vip_str}", "system")

        self.status_label.configure(text=f"Connected ({vip_str})", text_color="green")
        self.connect_btn.configure(text="Disconnect", state="normal")

        self.message_entry.configure(state="normal")
        self.send_btn.configure(state="normal")
        self.auth_btn.configure(state="normal")

        # Reset admin state
        self.is_admin = False
        self.admin_status.configure(text="Not authenticated", text_color="gray")
        self._hide_admin_panel()

    def _on_connection_failed(self, error: str):
        self.log_message(f"Connection failed: {error}", "red")
        messagebox.showerror("Connection Failed", f"Failed to connect:\n{error}")
        self.connect_btn.configure(state="normal")

    def disconnect(self):
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
                self.is_admin = False

                self.status_label.configure(text="Disconnected", text_color="red")
                self.connect_btn.configure(text="Connect")
                self.message_entry.configure(state="disabled")
                self.send_btn.configure(state="disabled")
                self.auth_btn.configure(state="disabled")

                self.admin_status.configure(text="Not authenticated", text_color="gray")
                self._hide_admin_panel()

                self._update_client_list([])
                self.display_message("Disconnected from server", "system")

    # ── Messaging ──

    def send_message(self):
        if not self.running or not self.client:
            return

        message = self.message_entry.get().strip()
        if not message:
            return

        try:
            if self.target_ip:
                pkt = Packet(S2C, message.encode(), dst_ip=self.target_ip)
                self.client.send(pkt, on_error="ignore")
                self.display_message(message, "sent")
            else:
                pkt = Packet(MSG, message.encode())
                self.client.send(pkt)
                self.display_message(message, "sent")

            self.message_entry.delete(0, "end")

        except Exception as e:
            self.log_message(f"Failed to send message: {e}", "red")
            messagebox.showerror("Send Error", str(e))

    def set_target(self):
        target = self.target_entry.get().strip().lower()
        if target == "server":
            self.target_ip = None
            self.log_message("Target set: Server")
            self.display_message("Target set to Server", "system")
        else:
            try:
                self.target_ip = ip_to_int(target)
                self.log_message(f"Target set: {target}")
                self.display_message(f"Target set to {target}", "system")
            except Exception as e:
                messagebox.showerror("Error", f"Invalid IP format: {e}")

    # ── C2C Tunnel ──

    def establish_tunnel(self):
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
                self.display_message(f"Secure tunnel to {target} already active", "system")
                return

            self.log_message(f"Establishing secure tunnel to {target}...")
            self.display_message(f"Establishing secure C2C tunnel to {target}...", "system")

            threading.Thread(target=self._establish_tunnel_thread,
                           args=(target_ip,), daemon=True).start()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse IP: {e}")

    def _establish_tunnel_thread(self, target_ip: int):
        try:
            self.client.do_c2c_handshake(c2c_vip=target_ip, use_dh=True)
            self.tunnels.add(target_ip)

            ip_str = int_to_ip(target_ip)
            self.after(0, lambda: self.log_message(f"Secure tunnel established with {ip_str}"))
            self.after(0, lambda: self.display_message(
                f"Encrypted C2C tunnel established with {ip_str}", "system"))

        except Exception as e:
            err_msg = str(e)
            self.after(0, lambda msg=err_msg: self.log_message(f"Tunnel failed: {msg}", "red"))
            self.after(0, lambda msg=err_msg: messagebox.showerror("Tunnel Error", msg))

    # ── Client List Request ──

    def request_clients(self):
        if not self.running or not self.client:
            messagebox.showwarning("Not Connected", "Please connect to server first")
            return

        try:
            self.client.send(Packet(GCL, b"request"))
            self.log_message("Requested clients list")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ── Admin Authentication ──

    def authenticate_admin(self):
        if not self.running or not self.client:
            messagebox.showwarning("Not Connected", "Please connect to server first")
            return

        token = self.token_entry.get().strip()
        if not token:
            messagebox.showwarning("Missing Token", "Please enter an admin token")
            return

        self.auth_btn.configure(state="disabled", text="Authing...")
        self.log_message("Authenticating as admin...")

        threading.Thread(target=self._auth_admin_thread, args=(token,), daemon=True).start()

    def _auth_admin_thread(self, token: str):
        self._admin_auth_event.clear()
        pkt = Packet(AUTH, token.encode())
        try:
            self.client.send(pkt)
        except Exception as e:
            self.after(0, lambda: self._auth_failed(f"Send error: {e}"))
            return

        if self._admin_auth_event.wait(timeout=5.0):
            if self._admin_auth_result:
                self.after(0, self._auth_succeeded)
            else:
                self.after(0, lambda: self._auth_failed("Invalid token"))
        else:
            self.after(0, lambda: self._auth_failed("Timeout waiting for response"))

    def _auth_succeeded(self):
        self.is_admin = True
        self.log_message("Authenticated as admin")
        self.display_message("Admin authentication successful", "admin")
        self.admin_status.configure(text="Admin", text_color="#8b5fc0")
        self.auth_btn.configure(state="normal", text="Authenticate")
        self._show_admin_panel()

    def _auth_failed(self, reason: str):
        self.log_message(f"Admin auth failed: {reason}", "red")
        self.display_message(f"Admin auth failed: {reason}", "admin")
        self.admin_status.configure(text="Auth failed", text_color="red")
        self.auth_btn.configure(state="normal", text="Authenticate")
        self.is_admin = False

    # ── Admin Commands ──

    def _send_admin_cmd(self):
        if not self.is_admin:
            messagebox.showwarning("Not Admin", "You must authenticate as admin first")
            return
        cmd = self.admin_cmd_entry.get().strip()
        if not cmd:
            return
        self._exec_admin_cmd(cmd)
        self.admin_cmd_entry.delete(0, "end")

    def _exec_admin_cmd(self, cmd: str):
        if not self.running or not self.client:
            return
        if not self.is_admin:
            self.log_message("Admin auth required for commands", "red")
            return

        threading.Thread(target=self._admin_cmd_thread, args=(cmd,), daemon=True).start()

    def _admin_cmd_thread(self, cmd: str):
        self._admin_cmd_event.clear()
        pkt = Packet(ADMIN, cmd.encode())
        try:
            self.client.send(pkt)
        except Exception as e:
            self.after(0, lambda: self.log_message(f"Admin cmd error: {e}", "red"))
            return

        if self._admin_cmd_event.wait(timeout=10.0):
            result = self._admin_cmd_result
            self.after(0, lambda: self._display_admin_result(result))
        else:
            self.after(0, lambda: self.log_message("Admin cmd timed out", "red"))

    def _display_admin_result(self, result: str):
        if result.startswith("ERR:"):
            self.log_message(f"Admin error: {result}", "red")
            self.display_message(f"Admin error: {result[4:]}", "admin")
        else:
            for line in result.split("\n"):
                if line.strip():
                    self.display_message(line.strip(), "admin")
            self.log_message("Admin command completed")

    # ── Broadcast ──

    def _send_broadcast(self):
        if not self.is_admin:
            messagebox.showwarning("Not Admin", "You must authenticate as admin first")
            return
        message = self.message_entry.get().strip()
        if not message:
            messagebox.showwarning("Empty Message", "Type a broadcast message first")
            return

        self.message_entry.delete(0, "end")
        threading.Thread(target=self._broadcast_thread, args=(message,), daemon=True).start()

    def _broadcast_thread(self, message: str):
        self._admin_bcst_event.clear()
        pkt = Packet(BCST, message.encode())
        try:
            self.client.send(pkt)
        except Exception as e:
            self.after(0, lambda: self.log_message(f"Broadcast error: {e}", "red"))
            return

        if self._admin_bcst_event.wait(timeout=10.0):
            result = self._admin_bcst_result
            self.after(0, lambda: self.log_message(f"Broadcast: {result}"))
            self.after(0, lambda: self.display_message(f"Broadcast sent: {result}", "admin"))
        else:
            self.after(0, lambda: self.log_message("Broadcast timed out", "red"))

    # ── Receive Loop ──

    def receive_loop(self):
        while self.running:
            try:
                pkt = self.client.receive(on_error="ignore")

                if pkt is None:
                    time.sleep(0.05)
                    continue

                # Admin response routing (via thread-safe events)
                if pkt.type == AUTH:
                    self._admin_auth_result = (pkt.payload == b"OK")
                    self._admin_auth_event.set()

                elif pkt.type == ADMIN:
                    self._admin_cmd_result = pkt.payload.decode(errors='ignore')
                    self._admin_cmd_event.set()

                elif pkt.type == BCST:
                    self._admin_bcst_result = pkt.payload.decode(errors='ignore')
                    self._admin_bcst_event.set()

                else:
                    self.process_packet(pkt)

            except Exception as e:
                if self.running:
                    self.after(0, lambda e=e: self.log_message(f"Receive error: {e}", "red"))
                time.sleep(0.5)

        if self.running:
            self.after(0, lambda: self.log_message("Connection lost", "red"))
            self.after(0, self.disconnect)

    def process_packet(self, pkt: Packet):
        if pkt.type == S2C:
            sender = int_to_ip(pkt.src_ip) if pkt.src_ip else "Unknown"
            message = pkt.payload.decode(errors='ignore')
            self.after(0, lambda: self.display_message(f"From {sender}: {message}", "received"))

        elif pkt.type == MSG:
            message = pkt.payload.decode(errors='ignore')
            self.after(0, lambda: self.display_message(f"Server: {message}", "received"))

        elif pkt.type == GCL:
            data = pkt.payload
            ips = []
            if len(data) % 4 != 0:
                try:
                    client_ip = int.from_bytes(data, 'big')
                    ips.append(client_ip)
                except Exception:
                    self.after(0, lambda: self.log_message("Malformed clients list payload", "red"))
            else:
                for i in range(0, len(data), 4):
                    client_ip = int.from_bytes(data[i:i+4], 'big')
                    ips.append(client_ip)
            if ips:
                self.after(0, lambda ips=ips: self._update_client_list(ips))

        elif pkt.type == ERR:
            error = pkt.payload.decode(errors='ignore')
            self.after(0, lambda: self.log_message(f"Server error: {error}", "red"))

        elif pkt.type == EXIT:
            self.after(0, lambda: self.log_message("Server requested disconnect"))
            self.after(0, self.disconnect)

        elif pkt.type == PING:
            try:
                self.client.send(Packet(PING, b"pong"))
            except Exception:
                pass

    # ── Cleanup ──

    def on_closing(self):
        if self.running:
            self.disconnect()
        self.destroy()


class GUILogHandler(logging.Handler):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def emit(self, record):
        msg = self.format(record)
        try:
            self.callback(msg)
        except Exception:
            pass


def main():
    app = DoSPGUIClient()
    app.mainloop()


if __name__ == "__main__":
    main()
