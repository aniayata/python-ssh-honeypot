import paramiko
import sys
import threading

def receive_data(channel):
    while True:
        try:
            data = channel.recv(1024)
            if not data:
                break
            sys.stdout.write(data.decode("utf-8", errors="ignore"))
            sys.stdout.flush()
        except Exception:
            break

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    print("[*] Connecting to Honeypot on port 2222...")
    try:
        client.connect("127.0.0.1", port=2222, username="ania", password="codergirl")
        
        # Open transport channel directly without requiring PTY allocation
        transport = client.get_transport()
        channel = transport.open_session()
        channel.invoke_shell()

        # Thread to read responses from server asynchronously
        thread = threading.Thread(target=receive_data, args=(channel,))
        thread.daemon = True
        thread.start()

        # Main loop to send keyboard input
        while True:
            cmd = input()
            channel.send(cmd + "\n")
            if cmd.strip() == "exit":
                break

    except Exception as e:
        print(f"[-] Connection error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    main() 