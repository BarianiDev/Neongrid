import socket
import threading

def scan_port(ip, port):

    try:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip, port))

        if result == 0:
            print(f"Port {port} is open on {ip}")

        sock.close()

    except socket.gaierror:
        print("[ERROR] Hostname could not be resolved.")

    except socket.error:
        print("[ERROR] Could not connect to server.")

    except KeyboardInterrupt: 
        print("\n[INFO] Scan interrupted by user.")
        exit()

for port in range(1, 1025):
    thread = threading.Thread(target=scan_port, args=("scanme.nmap.org", port))
    thread.start()
    
