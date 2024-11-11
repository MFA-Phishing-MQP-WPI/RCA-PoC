import socket
import threading

class AccessPointShell:
    def __init__(self, ap_host, ap_port):
        self.ap_host = ap_host
        self.ap_port = ap_port
        self.mode = "WAP"

    def displayable(self) -> str:
        return 'secure' if self.mode == 'WAP' else 'rogue'

    def set_mode(self, mode):
        """Set the mode of the access point."""
        if mode in ["WAP", "RWAP"]:
            self.mode = mode
            print(f"Access Point mode set to: {self.mode}")
        else:
            print("Invalid mode. Use 'WAP' for normal or 'RWAP' for rogue mode.")

    def handle_client(self, conn, addr):
        print(f"Victim connected from {addr}")
        try:
            while True:
                victim_request = conn.recv(1024)
                if not victim_request:
                    break

                if self.mode == "WAP":
                    target_host, target_port = self.determine_target(victim_request)
                    response = self.forward_request(victim_request, target_host, target_port)
                    if response:
                        conn.sendall(response)
                    else:
                        print("No response from target.")
        except Exception as e:
            print(f"Error handling victim connection: {e}")
        finally:
            conn.close()
            print(f"Connection with victim {addr} closed.")

    def determine_target(self, request):
        """Determine the target based on the request. Simplified for this PoC."""
        if b"login.microsoft.com" in request:
            # If the request is for Microsoft, route to Microsoft server
            return "localhost", 6666
        else:
            # Otherwise, assume it’s a DNS query
            return "localhost", 5555

    def forward_request(self, request, target_host, target_port):
        """Forward the request to the target and get the response."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_host, target_port))
                s.sendall(request)
                response = s.recv(1024)  # Read up to 1 KB response for simplicity
                
                # Ensure the response is encoded as UTF-8 (for text data like port numbers)
                if target_host == "localhost" and target_port == 5555:  # DNS response
                    return b'200' + str(int.from_bytes(response, 'big')).encode('utf-8')
                else:
                    return b'200' + response
        except Exception as e:
            print(f"Error forwarding request to {target_host}:{target_port} (responding with 404) - {e}")
            return b'404'

    def start(self):
        """Start the access point shell to listen for victim requests."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.ap_host, self.ap_port))
            s.listen()
            print(f"Access Point Shell running on {self.ap_host}:{self.ap_port} in {self.displayable()} mode...")
            while True:
                conn, addr = s.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()

# Main execution
if __name__ == "__main__":
    try:
        ap_shell = AccessPointShell("localhost", 7777)
        ap_shell.set_mode("WAP")  # WAP vs RWAP
        ap_shell.start()
    except KeyboardInterrupt:
        print("",end='\r')
