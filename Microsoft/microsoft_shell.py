import os
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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

def get_TLS_bytes() -> bytes:
    with open("microsoft_tls_certificate.json", "r") as f:
        return f.read().encode()

# Microsoft server that responds with SSL certificate and completes key exchange
def run_microsoft_server(microsoft_host, microsoft_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((microsoft_host, microsoft_port))
        s.listen()
        print("Microsoft server listening...")
        while True:
            conn, addr = s.accept()
            with conn:
                conn.sendall(get_TLS_bytes())

                # Step 2: Receive client's secret for Diffie-Hellman
                client_secret = conn.recv(1024)
                my_secret = os.urandom(16)
                conn.sendall(my_secret)

                # Create shared key
                shared_key = bytes(a ^ b for a, b in zip(my_secret, client_secret))

                # Step 3: Send and receive messages
                response = receive(conn, shared_key)
                if not response:
                    print("Received empty message from victim! Ending program.")
                    return
                print(f"Received message from victim: '{response}'\n")

                print(" > Responding with 'This is Microsoft'")
                if send("This is Microsoft", conn, shared_key):
                    print(" > Response sent successfully.")
                else:
                    print(" > Failed to send response!")

# Main execution
if __name__ == "__main__":
    try:
        run_microsoft_server("localhost", 6666)
    except KeyboardInterrupt:
        pass

