import os
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Optional

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

def receive(conn: socket.socket, shared_key: bytes) -> Optional[str]:
    try:
        data = conn.recv(1024)
        iv, encrypted_message = data[:16], data[16:]
        decryptor = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend()).decryptor()
        return decryptor.update(encrypted_message).decode()
    except Exception as e:
        print(f"Error receiving message: {e}")
        return None