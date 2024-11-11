import os
from typing import Optional, Union, List
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend



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
            print(f"Certificate saved to {filename}")
        except Exception as e:
            print(f"Error saving certificate to file: {e}")

            


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



def cert_is_authentic(sig: bytes, expected: bytes) -> bool:
    for ca in KNOWN_CAS:
        if ca.is_authentic(sig, expected):
            return True
        print(f' <debug> failed: {ca.name}')
    return False




def send(msg: str, conn: socket.socket, shared_key: bytes) -> bool:
    try:
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend()).encryptor()
        encrypted_message = iv + encryptor.update(msg.encode())
        conn.sendall(encrypted_message)
        return True
    except Exception as e:
        print(f"Error sending message: {e}")
        return False



def receive(conn: socket.socket, shared_key: bytes) -> str:
    try:
        data = conn.recv(1024)
        iv, encrypted_message = data[:16], data[16:]
        decryptor = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend()).decryptor()
        return decryptor.update(encrypted_message).decode()
    except Exception as e:
        print(f"Error receiving message: {e}")
        return ""


if __name__ == '__main__':
    print("\nALL KNOWN CAs TO VICTIM\n")
    for ca in KNOWN_CAS:
        print(ca)