import socket
import json
from VUtils import TLS_Certificate, cert_is_authentic
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from typing import List



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



################################################################



def query_dns(dns_host, dns_port, to:str="login.microsoft.com"):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((dns_host, dns_port))
            s.sendall(to.encode())
            port = int(s.recv(1024).decode())
        return port
    except ConnectionRefusedError:
        print("\n\tCould not connect to DNS. Is it running?\n")
        exit()



def connect_to_web_service(host, port, target:str='login.microsoft.com'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
        except ConnectionRefusedError:
            print(f"\n\tCould not connect to web_service({target} at {port}). Is it running?\n")
            exit()
        
        cert_data = s.recv(4096).decode()  # Receive the JSON data of the certificate
        cert_dict = json.loads(cert_data)
        
        received_certificate = TLS_Certificate(
            subject=cert_dict["subject"],
            issuer=cert_dict["issuer"],
            serial_number=cert_dict["serial_number"],
            signature=cert_dict["signature"],
            not_before=cert_dict["validity_period"]["not_before"],
            not_after=cert_dict["validity_period"]["not_after"]
        )

        if cert_is_authentic( received_certificate.get_signature(), received_certificate.get_expected_data() ):
            print("SSL Certificate successfully verified.")
        else:
            print("SSL Certificate authenticity could not be verified. (HTTPS FAILED) Aborting.")
            return

        my_secret = os.urandom(16)
        s.sendall(my_secret)
        their_secret = s.recv(1024)

        shared_key = bytes(a ^ b for a, b in zip(my_secret, their_secret))

        if send("This is the victim, announce yourself!", s, shared_key):
            print("Message sent to Microsoft.")
        
        response = receive(s, shared_key)
        if not response:
            print("Failed to receive a response from Microsoft.")
        else:
            print(f"Microsoft says: '{response}'")



if __name__ == "__main__":
    try:
        target = 'login.microsoft.com'
        dns_port = query_dns("localhost", 5555, to=target)
        if dns_port == -1:
            print(f"DNS could not find {target}")
            exit()
        connect_to_web_service("localhost", dns_port, target=target)
    except KeyboardInterrupt:
        print("",end='\r')
