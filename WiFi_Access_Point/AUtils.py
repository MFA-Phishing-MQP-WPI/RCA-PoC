import sys
import socket
import random
import time
import os
from typing import Optional, List, Union, Tuple
from datetime import datetime, timezone, timedelta

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

def pull_info_from_request(request: bytes) -> Tuple[str, str, str, bytes]:
    message_type_to_display = 'un-encrypted_get_request='
    msg_type = 'get-request'
    display_next = ''
    if b'<flag: key_exchange>' == request[:20]:
        message_type_to_display = 'un-encrypted_key_exchange='
        msg_type = 'public-key'
        request = request[20:]
        display_next = '       > Initiating key exchange'
    elif b'<flag: https_msg>' == request[:17]:
        message_type_to_display = 'encrypted_HTTPS_request='
        msg_type = 'https-secure'
        display_next = '       > Initiating secure https message'
        request = request[17:]
    else:
        display_next = '       > Initiating base message'
    return message_type_to_display, msg_type, display_next, request

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
            if str(response_code) == '404':
                msg_type = 'PageNotFoundError'
            elif str(response_code) == '403':
                msg_type = 'PageForbiddenError'
            elif str(response_code) == '402':
                msg_type = 'Access Error'
            elif str(response_code) == '400':
                msg_type = 'Server Unreachable'
            else:
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

operating_mode: str = 'WAP'
require_ca: bool = False

def get_operating_mode() -> str:
    return operating_mode

def is_m_ca_required() -> bool:
    return require_ca

def display_usage() -> None:
    print("\nUSAGE:")
    print('\n\tpython3 access_point_shell.py [wap rwap] [OPTIONAL: -require_malicious_ca]\n')

def wrong_args(args) -> bool:
    """Check if the arguments are invalid."""
    if len(args) < 2 or len(args) > 3:
        return True
    mode_arg = args[1].lower()
    if mode_arg not in ['wap', 'rwap']:
        return True
    if len(args) == 3:
        ca_arg = args[2].lower()
        if ca_arg != '-require_malicious_ca':
            return True
    return False

def update_settings() -> None:
    global operating_mode, require_ca
    if wrong_args(sys.argv):
        display_usage()
        sys.exit(1)
    operating_mode = sys.argv[1].upper()
    require_ca = False if operating_mode == 'WAP' else '-require_malicious_ca' in [arg.lower() for arg in sys.argv]  

update_settings()
