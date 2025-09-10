import socket

target = "scanme.nmap.org"
port = 80

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    result = sock.connect_ex((target, port))
    if result == 0:
        print(f"Port {port} open")
    else:
        print(f"Port {port} closed (code {result})")
    sock.close()
except Exception as e:
    print(f"Error: {e}")
