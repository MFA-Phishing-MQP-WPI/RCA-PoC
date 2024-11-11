import os
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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