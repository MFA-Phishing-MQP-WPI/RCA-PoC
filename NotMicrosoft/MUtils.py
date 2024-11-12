import os
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Optional, Tuple
import base64

def to_b64(raw: bytes) -> bytes:
    return base64.b64encode(raw)
def from_b64(b64_bytes: bytes) -> bytes:
    return base64.b64decode(b64_bytes.decode())

def send(msg: str, conn: socket.socket, shared_key: bytes) -> bool:
    try:
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend()).encryptor()
        encrypted_message = iv + encryptor.update(msg.encode())
        conn.sendall(encrypted_message)
        return True
    except Exception as e:
        print(f" > SEND ERROR: sending message: {e}")
        return False

def receive(conn: socket.socket, shared_key: bytes) -> Optional[str]:
    try:
        data = b''
        while len(data) < 16:
            data = conn.recv(1024)
            print(f'   > recieved data of size {len(data)}')
        iv, encrypted_message = data[:16], data[16:]
        decryptor = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend()).decryptor()
        return decryptor.update(encrypted_message).decode()
    except Exception as e:
        print(f" > RECEIVE ERROR: receiving message: {e}")
        return None

def get_port(addr:str) -> str:
    if type(addr) != str:
        addr = f'{addr}'
    if ',' not in addr:
        return addr
    return addr.split(', ', 1)[1][:-1]

def encrypt(msg: str, shared_key: bytes) -> bytes:
    try:
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend()).encryptor()
        encrypted_message = iv + encryptor.update(msg.encode())
        return encrypted_message
    except Exception as e:
        print(f"Error encrypting message: {e}")
        return b''

def decrypt(encrypted_msg: bytes, shared_key: bytes) -> str:
    try:
        iv, ciphertext = encrypted_msg[:16], encrypted_msg[16:]
        decryptor = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend()).decryptor()
        decrypted_message = decryptor.update(ciphertext)
        return decrypted_message.decode()
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return b''
    
def decoder(b_request: bytes) -> Tuple[str, bytes]:
    try:
        key_identifier = b_request[:12].decode()
        if key_identifier == 'KEY_EXCHANGE':
            return ('KEY_EXCHANGE', b_request[12:])
    except UnicodeDecodeError:
        pass

    try:
        https_identifier = b_request[:13].decode()
        if https_identifier == 'HTTPS_MESSAGE':
            return ('HTTPS_MESSAGE', b_request[13:])
    except UnicodeDecodeError:
        pass

    try:
        b_request.decode().strip()
        return ('None', b_request)
    except UnicodeDecodeError:
        pass

    return ('UNKNOWN', b_request)