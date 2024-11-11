import json
from datetime import datetime
import os
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class TLS_Certificate:
    def __init__(self, subject, issuer, serial_number, signature, not_before, not_after):
        self.subject = subject
        self.issuer = issuer
        self.serial_number = serial_number
        self.signature = signature
        self.validity_period = {
            "not_before": not_before,
            "not_after": not_after
        }

    def get_url(self) -> str:
        return self.subject["common_name"]
    def get_signature(self) -> bytes:
        return bytes.fromhex(self.signature)
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
        # Save the certificate JSON to a file
        try:
            with open(filename, 'w') as file:
                file.write(self.to_json())
            print(f"Certificate saved to {filename}")
        except Exception as e:
            print(f"Error saving certificate to file: {e}")


def Test_TSL_Certificate():
    # Sample certificate details
    subject = {
        "common_name": "www.example.com",
        "organization": "Example Inc.",
        "country": "US"
    }
    issuer = {
        "common_name": "Example CA",
        "organization": "Example CA Ltd.",
        "country": "US"
    }
    serial_number = "123456789ABCDEF"
    signature = "abc123signatureXYZ"
    not_before = datetime(2024, 1, 1)
    not_after = datetime(2025, 1, 1)

    # Create a TLS certificate instance
    cert = TLS_Certificate(subject, issuer, serial_number, signature, not_before, not_after)
    
    # Print the certificate in JSON format
    print(cert.to_json())

    # Save the certificate to a file
    cert.save_to_file("tls_certificate.json")

# import os
# import socket
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend

# Send an encrypted message
def send(msg: str, s: socket.socket, encryptor) -> bool:
    try:
        iv = os.urandom(16)
        encrypted_message = iv + encryptor.update(msg.encode())
        s.sendall(encrypted_message)
        return True
    except Exception as e:
        print(f"Error sending message: {e}")
        return False

# Receive and decrypt a message
def receive(conn: socket.socket, decryptor) -> str:
    try:
        # s.listen()
        # conn, _ = s.accept()
        # with conn:
            data = conn.recv(1024)
            iv, encrypted_message = data[:16], data[16:]
            decryptor = Cipher(algorithms.AES(decryptor.key), modes.CFB(iv), backend=default_backend()).decryptor()
            return decryptor.update(encrypted_message).decode()
    except Exception as e:
        print(f"Error receiving message: {e}")
        return ""


if __name__ == '__main__':
    Test_TSL_Certificate()
