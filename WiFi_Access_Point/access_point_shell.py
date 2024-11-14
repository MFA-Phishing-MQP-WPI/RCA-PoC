import socket
import threading
import time
import random
import sys
import os
from typing import Union, List, Optional, Tuple
from datetime import datetime, timezone, timedelta

from AUtils import get_operating_mode, is_m_ca_required

PHISHING_SERVER: int = 6665

PACKET_SNIFFER: str = 'sniffed_packets.txt'
KNOWN_PORTS = {
    '7777': 'Wi-Fi Access Point',
    '5555': 'DNS Server',
    '6666': 'Microsoft SSO Server',
    f'{PHISHING_SERVER}': 'Fake Microsoft Server',
    7777  : 'Wi-Fi Access Point',
    5555  : 'DNS Server',
    6666  : 'Microsoft SSO Server',
    PHISHING_SERVER  : 'Fake Microsoft Server'
}


def download_progress(
        load_time: float,
        prefix: str,
        bar_length:int = 40,
        total_steps:int = 100
    ):
    
    start_time = time.time()
    elapsed_time = 0

    while elapsed_time < load_time:
        elapsed_percentage = min(100, int((elapsed_time / load_time) * 100))
        progress = min(total_steps, elapsed_percentage + random.randint(1, 5))
        if progress > 100:
            progress = 100
        
        bar = "#" * (progress * bar_length // 100)
        sys.stdout.write(f"\r{prefix}[{bar:<{bar_length}}] {progress}%")
        sys.stdout.flush()
        time.sleep(random.uniform(0.05, 0.1))
        
        elapsed_time = time.time() - start_time
    sys.stdout.write("\r{}[{}] 100%\n".format(prefix, "#" * bar_length))
    sys.stdout.flush()

def evaluate(response: bytes) -> str:
    if len(response) < 3:
        return 'garbage'
    try:
        vals = response[:4].decode()
        all_numbers = True
        for v in vals[:3]:
            if v not in '0123456789':
                all_numbers = False
                break
        if all_numbers and vals[-1] == ' ':
            return 'get-response'
    except UnicodeDecodeError:
        pass
    try:
        response.decode()
        return 'plaintext'
    except UnicodeDecodeError:
        pass
    return 'unknown'

class FR:
    @staticmethod
    def get_paths(dir: str) -> List[str]:
        f = []
        for (dirpath, dirnames, filenames) in os.walk(dir):
            f.extend(filenames)
            break
        return filenames

    @staticmethod
    def read(file_path: str, mode: str = 'rb') -> Optional[Union[bytes, str]]:
        """Reads the content of a file. Returns None if file does not exist."""
        try:
            with open(file_path, mode) as f:
                return f.read()
        except FileNotFoundError:
            return None

    @staticmethod
    def write(file_path: str, content: Union[str, bytes], mode: str = 'wb') -> None:
        """Writes content to a file, creating directories if they do not exist."""
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, mode) as f:
            f.write(content)

    class path:
        @staticmethod
        def exists(file_path: str) -> bool:
            """Checks if a file exists at the specified path."""
            return os.path.exists(file_path)
        @staticmethod
        def create(file_path: str) -> None:
            """Creates a file path at the specified path."""
            os.makedirs(os.path.dirname(file_path), exist_ok=True)


def get_malcious_CA_bytes() -> bytes:
    return FR.read('RWAP_Root_CAs/MaliciousCA_public_key.pem')


def get_timestamp():
    now = datetime.now(timezone.utc)  # Get current time in UTC
    est_timezone = timezone(offset=-timedelta(hours=5))  # Define EST timezone
    est_time = now.astimezone(est_timezone)  # Convert to EST
    return est_time.strftime("%m/%d/%Y %I:%M:%S %p")


def msg_info(packet: bytes, more_info: str) -> tuple:
    """Extracts message type, response code, and message content from the packet."""
    try:
        decoded_packet = packet.decode()
    # except AttributeError as e:
    #     if f'{e}' == "'str' object has no attribute 'decode'":
    #         decoded_packet = packet
    #     else:
    #         print(f"`{e}`")
    #         raise e
    except UnicodeDecodeError:
        decoded_packet = None
    response_code = '200'
    if decoded_packet and len(packet) >= 3:
        response_code = decoded_packet[:3]
        decoded_packet = decoded_packet[4:]
    else:
        try:
            response_code = int(packet[:3].decode())
            packet = packet[4:]
        except:
            pass
    if decoded_packet == 'CERT_REQUEST':
        msg_type = "certificate req"
    elif decoded_packet == 'Connection Refused':
        msg_type = 'connection error'
    elif decoded_packet and decoded_packet.startswith('{\n    "subject": {\n        "common_name":'):
        msg_type = "certificate body"
    elif decoded_packet and (decoded_packet.endswith('.com') or decoded_packet.endswith('.org')):
        msg_type = "DNS resolution req"
    elif more_info == "public-key":
        msg_type = "diffie-hellman"
    elif more_info == "https-secure":
        msg_type = "https encrypted"
    # elif not decoded_packet:
    #     msg_type = "unknown"
    else:
        try:
            int(decoded_packet)
            msg_type = 'DNS resolution resp'
        except Exception:
            msg_type = "unknown"

    if decoded_packet:
        message = decoded_packet.replace('\n', '\\n')
    else:
        message = packet
    return (msg_type, response_code, message)


def add_to_file_mod(_from: str, _to: str, new_packet: bytes, old_packet: bytes, more_info:str):
    if new_packet == old_packet:
        add_to_file(_from, _to, new_packet, more_info)
        return
    add_to_file(_from, '', old_packet, more_info)
    add_to_file('', _to, new_packet, more_info, MODIFIED=True)


def add_to_file(_from: str, _to: str, packet: bytes, more_info:str, MODIFIED: bool = False):
    """Logs packet information including timestamp, source, AP indicator, destination, and response code."""
    if not os.path.exists(PACKET_SNIFFER):
        open(PACKET_SNIFFER, 'w').write('')  # Create the log file if it doesn't exist
    msg_type, response_code, message = msg_info(packet, more_info)
    mod = '*MOD*' if MODIFIED else ' ORG '
    fr = '  ' if _from == '' else '->'
    tr = '  ' if _to == '' else '->'
    # timestamp = get_timestamp() if not MODIFIED else ''
    with open(PACKET_SNIFFER, 'a') as f:
        log_entry = (
            get_timestamp().ljust(25) + 
            _from.ljust(6) + f' {fr} AP {tr} ' + _to.ljust(8) +
            f'{mod}   ' +
            f'{msg_type}'.ljust(23) +
            f'[{response_code}] '.ljust(8) +
            f'{message}\n'
        )
        f.write(log_entry)


def add_to_file_update():
    if not os.path.exists(PACKET_SNIFFER):
        open(PACKET_SNIFFER,'w').write('')
    else:
        open(PACKET_SNIFFER, 'a').write('\n\n\n')

def identify_port(port_str: str) -> str:
    if port_str not in KNOWN_PORTS.keys():
        return ''
    return f' ({KNOWN_PORTS[port_str]})'

def get_port(addr) -> str:
    addr = f'{addr}'
    if ',' not in addr:
        return addr
    return addr.split(', ', 1)[1][:-1]

def handle_first_time_connect(req: bytes, mode: str, conn: socket):
    try:
        question = req.decode()
    except UnicodeDecodeError:
        return False
    if question == 'connection request':
        print(' > User requests to connect to Wi-Fi AP')
        if mode == 'WAP' or not is_m_ca_required():
            print('   > Checking User\'s Root CAs')
            print('   > User passed all checks ...')
            print(' > allowing connection')
            conn.sendall(b'200 approved')
        else:
            print('   > Checking User\'s Root CAs')
            print('   > User failed (missing Malicious CA)')
            print(' > Denied User access with message "403 certificate missing"')
            conn.sendall(b'403 certificate missing')
        return True
    if question == 'download certificate' and mode == 'RWAP':
        print(' > User requests to download Malicious CA')
        conn.sendall(get_malcious_CA_bytes())
        print(' > Malicious CA sent to user')
        return True
    if question == 'infected connection request' and mode == 'RWAP':
        print(' > User requests to connect to Wi-Fi AP')
        print('   > Checking User\'s Root CAs')
        print('   > User passed all checks ... ')
        print(' > allowing connection')
        conn.sendall(b'200 approved')
        return True


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
            message_type = 'un-encrypted_get_request='
            msg_type = 'get-request'
            queue = ''
            if b'<flag: key_exchange>' == request[:20]:
                message_type = 'un-encrypted_key_exchange='
                msg_type = 'public-key'
                s.sendall(b'KEY_EXCHANGE')
                request = request[20:]
                queue = '       > Initiating key exchange'
                time.sleep(0.1)
            elif b'<flag: https_msg>' == request[:17]:
                message_type = 'encrypted_HTTPS_request='
                msg_type = 'https-secure'
                s.sendall(b'HTTPS_MESSAGE')
                queue = '       > Initiating secure https message'
                time.sleep(0.1)
                request = request[17:]
            else:
                queue = '       > Initiating base message'
            print(f'\n > New request from {client_port}: Send {message_type}"{request}" to "{target_port}"{identify_port(target_port)} (Expecting {expected_responses} responses)')
            add_to_file(str(client_port), str(target_port), b'200 ' + request, msg_type)
            print(queue)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.connect((target_host, target_port))
                except socket.error:
                    return ([b'402 Connection Refused'], ['connection failed'])
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
                        infos.append(msg_type)

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
