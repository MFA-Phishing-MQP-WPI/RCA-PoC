import socket
import threading
import time
from typing import List, Tuple

from AUtils import get_operating_mode, is_m_ca_required, identify_port, handle_first_time_connect, \
    get_port, add_to_file_mod, add_to_file, add_to_file_update, pull_info_from_request, PHISHING_SERVER


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
            print(f"\nAccess Point mode set to: {self.mode}")
            require = 'will' if is_m_ca_required() else 'will NOT'
            print(f"Access Point {require} require the malicious CA to connect\n")
        else:
            print(f"'{mode}' is an invalid mode. Use 'WAP' for normal or 'RWAP' for rogue mode.")

    def edit_DNS_response(self, responses: list, r_from) -> list:
        if identify_port(r_from) != ' (DNS Server)':
            return responses
        print('        > ROGUE: Identified response from DNS')
        result = []
        for b_response in responses:
            response = b_response.decode()
            print(f'        > ROGUE:   {response=}')
            status_code = response[:3]
            resolved_port = response[4:]
            if identify_port(resolved_port) == ' (Microsoft SSO Server)':
                new_response = f'{status_code} {PHISHING_SERVER}'
                print(f'        > ROGUE:     Replaced previous response with new response "{new_response}"')
                result.append(new_response.encode())
            else:
                result.append(b_response)
        print(f'        > ROGUE: Forwarding edited responses to client ...')
        return result

    def handle_client(self, conn: socket, addr):
        client_port = get_port(addr)
        print(f"\nClient connected from {client_port}")
        try:
            while True:
                # Expecting structured data: "<PORT> <MESSAGE> <EXPECTED_RESPONSES>"
                victim_request = conn.recv(1024)
                if not victim_request:
                    break
                try:
                    if handle_first_time_connect(victim_request, self.mode, conn):
                        continue
                    port_str = victim_request[:4].decode()
                    b_message = victim_request[5:-2]
                    expected_responses_str = victim_request[-2:].decode().strip()
                    target_port = int(port_str)
                    expected_responses = int(expected_responses_str)
                except ValueError:
                    print(f" > Received malformed request from {client_port}. Closing connection.")
                    conn.sendall(b'400 Malformed Request')
                    break

                
                (responses, infos) = self.forward_request(b_message, "localhost", target_port, expected_responses, client_port)
                prev_responses = responses

                if self.mode == 'RWAP':
                    responses = self.edit_DNS_response(responses, target_port)
                
                if responses:
                    for i, (response, prev_response, info) in enumerate(zip(responses, prev_responses, infos)):
                        add_to_file_mod(str(target_port), str(client_port), response, prev_response, info)
                        time.sleep(0.2)
                        print(f' > Forwarding response {i+1} to {client_port}')
                        conn.sendall(response)
                else:
                    print(f' > Forwarding "404 Target Unreachable" to {client_port}')
                    conn.sendall(b'404 Target Unreachable')

        except ValueError as e: ## REPLACE WITH EXCEPTION
            print(f"Error handling client {client_port} connection: {e}")
        finally:
            conn.close()
            print(f"Connection with client {client_port} closed.\n__________________________________________\n")

    def forward_request(self, request, target_host, target_port: int, expected_responses: int, client_port: str) -> Tuple[List[bytes], List[str]]:
        """Forward the request to the target and get the response(s)."""
        responses = []
        infos = []
        try:
            msg_type, msg_use, display_next, request = pull_info_from_request(request)
            try:
                s_request = request.decode()
            except:
                s_request = request
            print(f'\n > New request from {client_port}: Send {msg_type}"{s_request}" to "{target_port}"{identify_port(target_port)} (Expecting {expected_responses} responses)')
            add_to_file(str(client_port), str(target_port), b'200 ' + request, msg_use)
            print(display_next)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.connect((target_host, target_port))
                except socket.error:
                    return ([b'402 Connection Refused'], ['connection failed'])
                if msg_use == 'public-key':
                    s.sendall(b'KEY_EXCHANGE')
                    time.sleep(0.1)
                elif msg_use == 'https-secure':
                    s.sendall(b'HTTPS_MESSAGE')
                    time.sleep(0.1)
                time.sleep(0.1)
                s.sendall(request)
                print(f'     > Message sent')

                for _ in range(expected_responses):
                    response = s.recv(1024)  # Receive up to 1 KB response for simplicity
                    # add_to_file(target_port, client_port, response, evaluate(response))
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
                        infos.append('connection failed')
                        continue

                    if response_code != '200':
                        print(f'   > Response code is not 200; it is {response_code}')
                        responses.append(response)
                        infos.append('unknown error')
                    else:
                        message_to_display: bytes = b_message if len(b_message) < 80 else b_message[:80] + b' ...'
                        print(f'   > Decoded reply from {target_port}{identify_port(target_port)} as [code: {response_code}, message: {message_to_display}]')
                        responses.append(b'200 ' + b_message)
                        infos.append(msg_use)

            return (responses, infos)
        except Exception as e:
            print(f"Error forwarding request to {target_host}:{target_port} (responding with 404) - {e}")
            return ([b'404 Target Unreachable'], ['connection failed'])

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



if __name__ == "__main__":
    try:
        ap_shell = AccessPointShell("localhost", 7777)
        ap_shell.set_mode(get_operating_mode())
        ap_shell.start()
    except KeyboardInterrupt:
        print("\nAccess Point shutting down.")
    finally:
        add_to_file_update()
