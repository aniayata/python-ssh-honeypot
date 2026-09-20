import socket
import sys
import threading
import logging
import json
import time
import os
import urllib.request
import paramiko


WEBHOOK_URL = "" 

os.makedirs("logs", exist_ok=True)
LOG_FILE = "honeypot_activity.log"
JSON_LOG_FILE = os.path.join("logs", "honeypot_events.json")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

HOST_KEY_FILE = "honeypot.key"
if os.path.exists(HOST_KEY_FILE):
    HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_FILE)
else:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(HOST_KEY_FILE)

def send_alert(message):
    """Sends real-time alerts via Webhook (if URL provided)."""
    if not WEBHOOK_URL:
        return
    try:
        data = json.dumps({"content": message}).encode('utf-8')
        req = urllib.request.Request(WEBHOOK_URL, data=data, headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'})
        urllib.request.urlopen(req)
    except Exception as e:
        print(f"[-] Webhook failed: {e}")

def log_json_event(event_type, **kwargs):
    payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event_type,
        **kwargs
    }
    with open(JSON_LOG_FILE, "a") as f:
        f.write(json.dumps(payload) + "\n")

class ProductionHoneypot(paramiko.ServerInterface):
    def __init__(self, client_address):
        self.client_address = client_address
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_msg = f"Auth Attempt | IP: {self.client_address[0]} | User: {username} | Pass: {password}"
        logging.info(log_msg)
        print(f"[*] {log_msg}")
        log_json_event("AUTH_ATTEMPT", ip=self.client_address[0], port=self.client_address[1], username=username, password=password)
        send_alert(f"🚨 **Honeypot Auth Attempt**\n**IP**: `{self.client_address[0]}`\n**User**: `{username}`\n**Pass**: `{password}`")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_pty_request(self, channel, term, modes, submethods):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        return True

def interactive_shell(channel, client_ip):
    try:
        channel.send("Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n\r\n")
        channel.send("user@ubuntu-server:~$ ")

        current_dir = "~"
        buffer = ""
        while True:
            data = channel.recv(1024)
            if not data:
                break
            
            char_str = data.decode("utf-8", errors="ignore")
            
            for char in char_str:
                if char in ("\r", "\n"):
                    channel.send("\r\n")
                    cmd = buffer.strip()
                    if cmd:
                        logging.info(f"Command Executed | IP: {client_ip} | Command: {cmd}")
                        log_json_event("COMMAND_EXECUTED", ip=client_ip, command=cmd)
                        print(f"[!] {client_ip} executed: {cmd}")
                        send_alert(f"⚠️ **Command Executed** by `{client_ip}`: `{cmd}`")

                        # --- EXPANDED COMMAND EMULATION LOGIC ---
                        if cmd == "exit":
                            channel.send("logout\r\n")
                            channel.close()
                            return
                        elif cmd == "ls" or cmd == "ls -la":
                            channel.send("documents  downloads  secret_passwords.txt\r\n")
                        elif cmd == "whoami":
                            channel.send("root\r\n")
                        elif cmd == "id":
                            channel.send("uid=0(root) gid=0(root) groups=0(root)\r\n")
                        elif cmd == "pwd":
                            channel.send("/root\r\n" if current_dir == "~" else f"/root/{current_dir}\r\n")
                        elif cmd == "uname -a":
                            channel.send("Linux ubuntu-server 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n")
                        elif cmd.startswith("cat "):
                            filename = cmd.split(" ", 1)[1]
                            if "passwords" in filename:
                                channel.send("admin:SuperSecret123!\r\nroot:toor\r\ndb_user:sql_pass_2026\r\n")
                            elif filename in ("/etc/passwd", "passwd"):
                                channel.send("root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\nuser:x:1000:1000:user:/home/user:/bin/bash\r\n")
                            else:
                                channel.send(f"cat: {filename}: No such file or directory\r\n")
                        elif cmd.startswith("cd"):
                            parts = cmd.split()
                            if len(parts) > 1:
                                target = parts[1]
                                if target in ("documents", "downloads"):
                                    current_dir = target
                                elif target in ("..", "/"):
                                    current_dir = "~"
                                else:
                                    channel.send(f"bash: cd: {target}: No such file or directory\r\n")
                            else:
                                current_dir = "~"
                        else:
                            channel.send(f"bash: {cmd}: command not found\r\n")

                    prompt_path = "~" if current_dir == "~" else f"~/{current_dir}"
                    channel.send(f"user@ubuntu-server:{prompt_path}$ ")
                    buffer = ""
                else:
                    buffer += char
                    
    except Exception as e:
        print(f"[-] Shell session ended: {e}")
    finally:
        channel.close()

def handle_client(client_socket, client_address):
    client_ip = client_address[0]
    logging.info(f"Connection established from {client_ip}:{client_address[1]}")
    log_json_event("CONNECTION_ESTABLISHED", ip=client_ip, port=client_address[1])
    
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(HOST_KEY)
    
    server = ProductionHoneypot(client_address)
    try:
        transport.start_server(server=server)
    except Exception:
        return

    channel = transport.accept(20)
    if not channel:
        return

    server.event.wait(10)
    if not server.event.is_set():
        channel.close()
        return

    shell_thread = threading.Thread(target=interactive_shell, args=(channel, client_ip))
    shell_thread.start()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(("0.0.0.0", 2222))
        server_socket.listen(100)
        print("[*] Honeypot actively listening on port 2222...")
    except Exception as e:
        print(f"[-] Socket bind failed: {e}")
        sys.exit(1)

    while True:
        client_socket, client_address = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, client_address)).start()

if __name__ == "__main__":
    main()