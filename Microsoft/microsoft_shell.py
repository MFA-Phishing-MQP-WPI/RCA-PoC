import os
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from MUtils import get_port, encrypt, decrypt, to_b64, from_b64, decoder

DATAFILE = 'Data.txt'

def get_TLS_bytes() -> bytes:
    """Reads and returns the TLS certificate as bytes."""
    with open("microsoft_tls_certificate.json", "r") as f:
        return f.read().encode()

def run_microsoft_server(microsoft_host, microsoft_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((microsoft_host, microsoft_port))
        s.listen()
        print("Microsoft server listening...")
        while True:
            conn, addr = s.accept()
            client_port = get_port(addr)
            print(f"\nConnected by victim at {client_port}")
            with conn:
                try:
                    # Step 1: Wait for the TLS certificate request
                    b_request = conn.recv(1024)
                    id, request = decoder(b_request)
                    # request = b_request.decode().strip()
                    
                    if id == 'None' and "CERT_REQUEST" in request.decode().strip():
                        conn.sendall(b'200 ' + get_TLS_bytes())
                        print(f"> TLS certificate sent to {client_port}.")
                        continue  # Wait for the next request

                    # Step 2: Wait for Diffie-Hellman key exchange request
                    elif "KEY_EXCHANGE" == id:
                        client_secret = request
                        if not client_secret:
                            print(f" > Failed to receive {client_port}'s public key")
                            continue

                        my_secret = os.urandom(16)
                        conn.sendall(b'200 ' + my_secret)
                        print(f"> Sent server public key for Diffie-Hellman exchange to {client_port}")

                        # Generate shared key from received client secret
                        shared_key = bytes(a ^ b for a, b in zip(my_secret, client_secret))
                        print(f" > Derived shared key for {client_port} ({shared_key})")
                        continue  # Wait for the next request

                    # Step 3: Secure HTTPS message exchange
                    elif "HTTPS_MESSAGE" == id:
                        # encrypted_response = conn.recv(1024)
                        encrypted_response = from_b64(request)
                        response = decrypt(encrypted_response, shared_key)
                        if not response:
                            print(f" > Empty message from {client_port}! Aborting connection.")
                            continue
                        print(f"Received message from {client_port}: '{response}'")

                        # Step 4: Respond with encrypted identity
                        identity = open(DATAFILE, 'r').read().strip()
                        # iv = os.urandom(16)
                        # encryptor = Cipher(algorithms.AES(shared_key), modes.CFB(iv), backend=default_backend()).encryptor()
                        # encrypted_message = iv + encryptor.update(identity.encode())  # Prepend IV
                        encrypted_message = encrypt(identity, shared_key)

                        print(f" > Sending {client_port}: message='200 {identity}' (response code: 200, message: encrypted)")
                        conn.sendall(b'200 ' + encrypted_message)
                    else:
                        print(f" > Unrecognized request from {client_port} ({id=})")
                        print(f'   (request was "{request}")')
                except Exception as e:
                    print(f"Error during communication with {client_port}: {e}")
                    print()
                finally:
                    print(f"Connection with {client_port} closed.")
                    conn.close()

if __name__ == "__main__":
    try:
        while True:
            run_microsoft_server("localhost", 6666)
    except KeyboardInterrupt:
        print("\nMicrosoft server shutting down.")
