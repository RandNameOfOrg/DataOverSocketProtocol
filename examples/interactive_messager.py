import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dosp.client import Client
from dosp.iptools import ip_to_int, int_to_ip
from dosp.protocol import *
import threading


class InteractiveMessageClient:
    def __init__(self, server_ip="main.hosts.daniil10295.ru", vip=None):
        self.server_ip = server_ip
        self.vip = vip
        self.client: Client | None = None
        self.running = False
        self.target_ip = None

    def connect(self):
        # """Подключение к серверу"""
        try:
            self.client = Client(host=self.server_ip, vip=self.vip, fixed_vip=False)
            print(f"✅ Connected to {self.server_ip}")
            print(f"📍 Your vIP: {int_to_ip(self.client.vip_int) or 'unknown'}")
            return True
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False

    def send_message(self, message, target_ip=None):
        """Отправка сообщения"""
        try:
            if target_ip:
                packet = Packet(S2C, message.encode(), dst_ip=target_ip)
                self.client.send(packet, on_error="ignore")
                print(f"📤 To {int_to_ip(target_ip)}: {message}")
            else:
                packet = Packet(MSG, message.encode())
                self.client.send(packet)
                print(f"📤 To server: {message}")
        except Exception as e:
            print(f"❌ Send error: {e}")

    def set_target(self, ip_str):
        """Установка целевого IP для сообщений"""
        try:
            if ip_str.lower() == 'server':
                self.target_ip = None
                print("🎯 Target set: Server")
            else:
                self.target_ip = ip_to_int(ip_str)
                print(f"🎯 Target set: {ip_str}")
        except ValueError:
            print("❌ Invalid IP format. Use '7.10.0.2' or 'server'")

    def request_clients(self):
        """Запрос списка клиентов"""
        try:
            packet = Packet(GCL, b"get_clients")
            self.client.send(packet)
            print("📋 Clients list requested")
        except Exception as e:
            print(f"❌ Request clients error: {e}")

    @staticmethod
    def show_help():
        """Показать справку по командам"""
        print("\n📖 Available commands:")
        print("  /help - Show this help")
        print("  /target <ip> - Set target IP (e.g., /target 7.10.0.2)")
        print("  /target server - Send to server")
        print("  /clients - Request clients list")
        print("  /myip - Show my IP")
        print("  /exit - Disconnect and exit")
        print("  /clear - Clear screen")
        print("  <message> - Send text message to current target")
        print("")

    def input_handler(self):
        """Обработчик ввода с консоли"""
        while self.running:
            try:
                user_input = input().strip()

                if not user_input:
                    continue

                # Обработка команд
                if user_input.startswith('/'):
                    if user_input == '/exit':
                        self.running = False
                        break
                    elif user_input == '/help':
                        self.show_help()
                    elif user_input.startswith('/target '):
                        ip = user_input[8:].strip()
                        self.set_target(ip)
                    elif user_input == '/clients':
                        self.request_clients()
                    elif user_input == '/myip':
                        print(f"📍 My IP: {int_to_ip(self.client.vip_int)}")
                    elif user_input == '/clear':
                        print("\n" * 50)
                    else:
                        print("❌ Unknown command. Type /help for available commands.")
                else:
                    # Отправка обычного сообщения
                    self.send_message(user_input, self.target_ip)

            except EOFError:
                break
            except Exception as e:
                print(f"❌ Input error: {e}")

    def message_handler(self):
        """Обработчик входящих сообщений"""
        while self.running:
            try:
                pkt = self.client.receive()

                if pkt is None:
                    continue

                # Обработка разных типов пакетов
                if pkt.type == S2C:
                    sender_ip = int_to_ip(pkt.src_ip) if pkt.src_ip else "Unknown"
                    print(f"\n📨 From {sender_ip}: {pkt.payload.decode()}")
                    print("> ", end="", flush=True)

                elif pkt.type == MSG:
                    print(f"\n📨 Server: {pkt.payload.decode()}")
                    print("> ", end="", flush=True)

                elif pkt.type == PING:
                    self.client.send(Packet(PING, b"pong"))

                elif pkt.type == AIP:
                    print(f"\n📍 Assigned IP: {int_to_ip(pkt.src_ip)}")
                    print("> ", end="", flush=True)

                elif pkt.type == ERR:
                    print(f"\n❌ Error: {pkt.payload.decode()}")
                    print("> ", end="", flush=True)

                elif pkt.type == EXIT:
                    print("\n🔌 Server requested disconnect")
                    self.running = False
                    break
            except PacketError as e:
                if self.running:
                    print("\n [vnet.client] Packet error: " + str(e))
                if "[WinError 10038]" in str(e):
                    self.running = False
                    break
            except Exception as e:
                if self.running:
                    print(f"\n❌ Receive error: {e}")

    def run(self):
        """Основной цикл работы клиента"""
        if not self.connect():
            return

        self.running = True

        # Запускаем поток для обработки входящих сообщений
        receiver_thread = threading.Thread(target=self.message_handler)
        receiver_thread.daemon = True
        receiver_thread.start()

        print("\n🚀 Interactive Client Started!")
        print("💡 Type /help for available commands")
        print("💬 Start typing messages below:\n")
        print("> ", end="", flush=True)

        try:
            # Основной поток обрабатывает ввод пользователя
            self.input_handler()
        except KeyboardInterrupt:
            print("\n\n⏹️ Client stopped by user")
        except Exception as e:
            print(f"\n❌ Client error: {e}")
        finally:
            self.running = False
            if self.client is not None:
                self.client.close()
            print("👋 Disconnected")


# Простая версия для быстрого старта
def simple_interactive_client():
        """Простая интерактивная версия"""
    # try:
        with Client(host="127.0.0.1", vip="7.10.0.1") as client:
            print(f"✅ Connected to main.hosts.daniil10295.ru")
            print(f"📍 Your vIP: {int_to_ip(client.vip_int)}")
            print("\n💬 Type messages to send to server, Ctrl+C to exit\n")

            def receive_messages():
                while True:
                    try:
                        pkt = client.receive()
                        if pkt and pkt.type == S2C:
                            print(f"\n📨 From {int_to_ip(pkt.src_ip)}: {pkt.payload.decode()}")
                        elif pkt and pkt.type == MSG:
                            print(f"\n📨 Server: {pkt.payload.decode()}")
                    except:
                        break

            # Запускаем прием сообщений в отдельном потоке
            import threading
            receiver = threading.Thread(target=receive_messages)
            receiver.daemon = True
            receiver.start()
            print("HELLO")
            # Основной цикл ввода
            while True:
                try:
                    message = input("> ").strip()
                    if message:
                        if message.startswith('/'):
                            if message == '/exit':
                                break
                            elif message == '/help':
                                print("Commands: /exit, /help")
                            else:
                                print("Unknown command")
                        else:
                            client.send(Packet(MSG, message.encode()))
                            print(f"📤 Sent: {message}")
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Error: {e}")

    # except Exception as e:
    #     print(f"❌ Connection error: {e}")


# Использование
if __name__ == "__main__":
    print("=== 🚀 Interactive DoSP Client ===")
    print("using IMC client")
    client = InteractiveMessageClient("127.0.0.1", "7.10.0.1")
    client.run()