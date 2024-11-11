import socket
from typing import Optional

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
            self.websites[name] = port
    def get_port(self, website_name: str) -> Optional[int]:
        if website_name.lower() not in self.websites.keys():
            return None
        return self.websites[website_name.lower()]
    
DomainNameSystem: DNS = DNS('database')

# DNS shell to send the port number of Microsoft server
def run_dns_server(dns_host, dns_port, microsoft_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((dns_host, dns_port))
        s.listen()
        print("DNS server listening for requests...")
        while True:
            conn, addr = s.accept()
            with conn:
                domain = conn.recv(1024).decode()
                print(f" > looking up '{domain}' in the DNS system")
                port: Optional[int] = DomainNameSystem.get_port(domain)
                if not port:
                    print(f"Sent '-1' to {addr}\n")
                    conn.sendall(b'-1')
                else:
                    conn.sendall(port.encode())
                    print(f"Sent port {port} to {addr}\n")

# Main execution
if __name__ == "__main__":
    try:
        run_dns_server("localhost", 5555, 6666)  # Assume Microsoft is listening on port 6666
    except KeyboardInterrupt:
        pass
