import socket
import threading
from time import sleep


KNOWN_PORTS = {
    '7777': 'Wi-Fi Access Point',
    '5555': 'DNS Server',
    '6666': 'Microsoft SSO Server'
}

def identify_port(port_str: str) -> str:
    if port_str not in KNOWN_PORTS.keys():
        return ''
    return f' ({KNOWN_PORTS[port_str]})'

def get_port(addr) -> str:
    addr = f'{addr}'
    if ',' not in addr:
        return addr
    return addr.split(', ', 1)[1][:-1]

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
        client_port = get_port(addr)
        print(f"\nClient connected from {client_port}")
        try:
            while True:
                # Expecting structured data: "<PORT> <MESSAGE> <EXPECTED_RESPONSES>"
                victim_request = conn.recv(1024)
                if not victim_request:
                    break

                # Parse port, message, and expected responses
                try:
                    # decoded_request = victim_request.decode().strip()
                    # port_str, message, expected_responses_str = decoded_request.split(" ", 2)
                    port_str = victim_request[:4].decode()
                    b_message = victim_request[5:-2]
                    expected_responses_str = victim_request[-2:].decode().strip()
                    print(f'\n > New request from {client_port}: Send "{b_message}" to "{port_str}"{identify_port(port_str)} (Expecting {expected_responses_str} responses)')
                    target_port = int(port_str)
                    expected_responses = int(expected_responses_str)
                except ValueError:
                    print(f" > Received malformed request from {client_port}. Closing connection.")
                    conn.sendall(b'400 Malformed Request')
                    break

                # Forward the request to the specified target port
                responses = self.forward_request(b_message, "localhost", target_port, expected_responses)

                # Send the response(s) back to the victim
                if responses:
                    for i, response in enumerate(responses):
                        sleep(0.2)
                        sending: bytes = response if len(response) < 40 else response[:40] + b' ...'
                        print(f' > Forwarding response {i+1} to {client_port}\n\t(response{i+1}={sending})')
                        conn.sendall(response)
                else:
                    print(f' > Forwarding "404 Target Unreachable" to {client_port}')
                    conn.sendall(b'404 Target Unreachable')
                
                print(' > replied to client ... waiting for client to close connection')

        except Exception as e:
            print(f"Error handling client {client_port} connection: {e}")
        finally:
            conn.close()
            print(f"Connection with client {client_port} closed.\n__________________________________________\n")

    def forward_request(self, request, target_host, target_port, expected_responses) -> list:
        """Forward the request to the target and get the response(s)."""
        responses = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_host, target_port))
                print(f'   > Connected to {target_port}{identify_port(str(target_port))}')
                if b'<flag: key_exchange>' == request[:20]:
                    s.sendall(b'KEY_EXCHANGE')
                    request = request[20:]
                    print('       > Initiating key exchange')
                elif b'<flag: https_msg>' == request[:17]:
                    s.sendall(b'HTTPS_MESSAGE')
                    print('       > Initiating secure https message')
                    request = request[17:]
                else:
                    print('       > Initiating base message')
                s.sendall(request)
                print(f'     > Message sent')

                # Collect the specified number of responses
                for _ in range(expected_responses):
                    response = s.recv(1024)  # Receive up to 1 KB response for simplicity
                    response_to_display: bytes = response if len(response) < 40 else response[:40] + b' ...'
                    print(f'   {target_port}{identify_port(str(target_port))} replied with "{response_to_display}"')
                    
                    try:
                        if len(response) < 3:
                            response_code, response = '304', b'304 No Response From Web-Server'
                        else:
                            b_response_code, b_message = response[:3], response[4:]
                            response_code = b_response_code.decode()
                    except UnicodeDecodeError:
                        print(f'   > Received response ({response}) from target ({target_port})')
                        print(f'   > Could not convert response to string, returning "404 failed to connect"')
                        responses.append(b'404 failed to connect')
                        continue

                    # Check response code and handle accordingly
                    if response_code != '200':
                        print(f'   > Response code is not 200; it is {response_code}')
                        responses.append(response)
                    else:
                        message_to_display: bytes = b_message if len(b_message) < 40 else b_message[:40] + b' ...'
                        print(f'   > Decoded reply from {target_port} as [code: {response_code}, message: "{message_to_display}"]')
                        responses.append(b'200 ' + b_message)

            return responses
        except Exception as e:
            print(f"Error forwarding request to {target_host}:{target_port} (responding with 404) - {e}")
            return [b'404 Target Unreachable']

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
        print("\nAccess Point shutting down.")
