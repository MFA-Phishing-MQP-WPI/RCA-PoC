import socket
from typing import Optional

def get_port(addr:str) -> str:
    if type(addr) != str:
        addr = f'{addr}'
    if ',' not in addr:
        return addr
    return addr.split(', ', 1)[1][:-1]

class DNS:
    def __init__(self, database_filename: str):
        self.dbn: str = database_filename
        self.websites: dict = {}
        self._load()

    def _load(self):
        lines = open(self.dbn, 'r').read().split('\n')
        for line in lines:
            if ':' not in line:
                continue
            name, port = line.split(':')
            self.websites[name.strip().lower()] = int(port.strip())  # Ensure ports are integers

    def get_port(self, website_name: str) -> Optional[int]:
        """Look up the port for a given website name."""
        return self.websites.get(website_name.lower())

DomainNameSystem = DNS('database')

def run_dns_server(dns_host, dns_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((dns_host, dns_port))
        s.listen()
        print("DNS server listening for requests...")
        while True:
            conn, addr = s.accept()
            with conn:
                client_port = get_port(addr)
                domain = conn.recv(1024).decode().strip() 
                print(f'\nReceived request from {client_port} to resolve URL({domain})')  
                print(f" > Looking up '{domain}' in the DNS system")
                
                port = DomainNameSystem.get_port(domain)
                if port is None:
                    print(f"DNS lookup failed for '{domain}'. Sending '404' to {client_port}")
                    conn.sendall(b'404 Not Found')  # Indicates lookup failure
                    print(f"Sent 'Not Found' to {client_port} (with status code: 404)")
                else:
                    response = f"200 {port}".encode('utf-8')  # Format as "200 <port>"
                    conn.sendall(response)  # Send the response as bytes
                    print(f"Sent port {port} to {client_port} (with status code: 200)")

if __name__ == "__main__":
    try:
        run_dns_server("localhost", 5555)
    except KeyboardInterrupt:
        print("\nDNS server shutting down.")
