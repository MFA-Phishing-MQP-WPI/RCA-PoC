import os
from typing import Optional, Union, List
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import socket
import base64
import time
import random
import sys

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

def installing(load_time: float):
    cursor = '|/-\\'
    start_time = time.time()
    elapsed_time = 0

    while elapsed_time < load_time:
        for c in cursor:
            sys.stdout.write(f"\rInstalling CA {c}")
            sys.stdout.flush()
            time.sleep(0.1)
            
            elapsed_time = time.time() - start_time
            if elapsed_time >= load_time:
                break

    sys.stdout.write("\rInstalling complete      \n")
    sys.stdout.flush()




verbose: bool = False

def is_verbose() -> bool:
    return verbose

class CA:
    def __init__(self, name: str, pk: bytes):
        self.name = name
        self.public_key = pk

    def is_authentic(self, signed_data: bytes, expected_data: bytes) -> bool:
        return CA.authenticate(self.public_key, signed_data, expected_data=expected_data)
    
    def __str__(self) -> str:
        newline = '\n'
        newline_tab = '\n\t'
        return f'{self.name}:\n\t{self.public_key.decode().replace(newline, newline_tab)}\n'
    
    def __repr__(self) -> str:
        return self.__str__()
    

    @staticmethod
    def authenticate(public_key: bytes, signed_data: bytes, expected_data: bytes = None) -> bool:
        """Authenticates by verifying that signed_data matches expected_data using the public key."""
        try:
            # Load the public key from PEM format
            pub_key = serialization.load_pem_public_key(
                public_key,
                backend=default_backend()
            )

            pub_key.verify(
                signed_data,
                expected_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False



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



class TLS_Certificate:
    def __init__(self, subject, issuer, serial_number, signature:str, not_before, not_after):
        self.subject = subject
        self.issuer = issuer
        self.serial_number = serial_number
        self.signature:str = signature
        self.validity_period = {
            "not_before": not_before,
            "not_after": not_after
        }

    def get_url(self) -> str:
        return self.subject["common_name"]
    def get_signature(self) -> bytes:
        return bytes.fromhex(self.signature) # bytes.fromhex(self.signature)
    def get_expected_data(self) -> bytes:
        return self.to_signable()

    def to_json(self):
        # Convert the certificate to a JSON string
        return json.dumps(self.__dict__, default=str, indent=4)

    def to_signable(self) -> bytes:
        temp = self.signature
        self.signature = None
        result = self.to_json().encode('utf-8')
        self.signature = temp
        return result

    def save_to_file(self, filename):
        try:
            with open(filename, 'w') as file:
                file.write(self.to_json())
            if is_verbose(): print(f"Certificate saved to {filename}")
        except Exception as e:
            if is_verbose(): print(f"Error saving certificate to file: {e}")


            


def get_CAs(root_ca_folder:str='RootCertificates') -> List[CA]:
    files = [ file 
            for file 
            in FR.get_paths(root_ca_folder) 
            if file.endswith('_public_key.pem')
    ]
    return [
        CA(
            file.split('_public_key.pem')[0],
            FR.read(f'{root_ca_folder}/{file}')
        ) for file in files
    ]



KNOWN_CAS: List[CA] = get_CAs()

def refresh_CAs():
    global KNOWN_CAS
    KNOWN_CAS = get_CAs()

def known_CA_names():
    refresh_CAs()
    global KNOWN_CAS
    return [ca.name for ca in KNOWN_CAS]



def TLS_is_authentic(tls: TLS_Certificate, for_url: str):
    url_match: bool = (tls.get_url() == for_url)
    if url_match:
        if is_verbose(): (f'      > TLS certificate for "{tls.get_url()}" matches the target url')
    else:
        if is_verbose(): print(f'  !!  > TLS certificate for "{tls.get_url()}" does NOT match the target url({for_url})')

    return url_match and cert_is_authentic(
        tls.get_signature(),
        tls.get_expected_data()
    )

def cert_is_authentic(sig: bytes, expected: bytes) -> bool:
    for ca in KNOWN_CAS:
        if ca.is_authentic(sig, expected):
            if is_verbose(): print(f'      > Authenticated TLS using hardcoded root-CA({ca.name})\'s public key')
            return True
    if is_verbose(): print(f'      > Failed to authenticate TLS using hardcoded root-CAs: [{", ".join([ca.name for ca in KNOWN_CAS])}]')
    return False

def cas_display() -> str:
    return ", ".join([ca.name for ca in KNOWN_CAS])


def send(msg: str, conn: socket.socket, shared_key: bytes, target_port: int) -> bool:
    """
    Sends an encrypted message to the Access Point with target port information.
    """
    try:
        # Prepare IV and encrypt the message
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend()).encryptor()
        encrypted_message = iv + encryptor.update(msg.encode())
        
        # Send formatted request to Access Point
        request = f"{target_port} ".encode() + encrypted_message
        conn.sendall(request)
        return True
    except Exception as e:
        if is_verbose(): print(f"Error sending message: {e}")
        return False

def encrypt(msg: str, shared_key: bytes) -> bytes:
    try:
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend()).encryptor()
        encrypted_message = iv + encryptor.update(msg.encode())
        return encrypted_message
    except Exception as e:
        if is_verbose(): print(f"Error encrypting message: {e}")
        return b''

def decrypt(encrypted_msg: bytes, shared_key: bytes) -> str:
    try:
        iv, ciphertext = encrypted_msg[:16], encrypted_msg[16:]
        decryptor = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend()).decryptor()
        decrypted_message = decryptor.update(ciphertext)
        return decrypted_message.decode()
    except Exception as e:
        if is_verbose(): print(f"Error decrypting message: {e}")
        return b''

def receive(conn: socket.socket, shared_key: bytes) -> str:
    """
    Receives an encrypted message from the Access Point and decrypts it.
    """
    try:
        data = conn.recv(1024)
        if len(data) < 16:
            if is_verbose(): print("Error: Received data too short to contain IV.")
            return ""
        
        iv, encrypted_message = data[:16], data[16:]
        decryptor = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend()).decryptor()
        return decryptor.update(encrypted_message).decode()
    except Exception as e:
        if is_verbose(): print(f"Error receiving message: {e}")
        return ""

def to_b64(raw: bytes) -> bytes:
    return base64.b64encode(raw)
def from_b64(b64_bytes: bytes) -> bytes:
    return base64.b64decode(b64_bytes.decode())

def edit_verbose():
    if len(sys.argv) != 1 and (len(sys.argv) != 2 or sys.argv[1].lower() not in ["-v", "-verbose"]):
        print('USAGE:  python3 victim_shell.py')
        print('USAGE:  python3 victim_shell.py [-v -verbose]')
    if len(sys.argv) == 2:
        global verbose
        verbose = True

def display_CAs():
    print("\nALL KNOWN CAs TO VICTIM\n")
    for ca in KNOWN_CAS:
        print(ca)

if __name__ == '__main__':
    display_CAs()