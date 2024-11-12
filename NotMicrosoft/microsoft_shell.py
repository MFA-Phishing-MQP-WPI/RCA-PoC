import os
import socket
from MUtils import get_port, encrypt, decrypt, from_b64, decoder

DATAFILE = 'Data.txt'
TIME_OUT_TIME = 5.0
CERT_LOCATION = 'malicious_microsoft_tls_certificate.json'

def get_TLS_bytes() -> bytes:
    with open(CERT_LOCATION, "r") as f:
        return f.read().encode()

def run_fake_server(fake_host, fake_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((fake_host, fake_port))
        s.listen()
        print("Fake server listening...")
        while True:
            conn, addr = s.accept()
            client_port = get_port(addr)
            print(f"\nConnected by victim at {client_port}")
            with conn:
                try:
                    conn.settimeout(TIME_OUT_TIME)
                    b_request = conn.recv(1024)
                    id, request = decoder(b_request)
                    
                    if id == 'None' and "CERT_REQUEST" in request.decode().strip():
                        conn.sendall(b'200 ' + get_TLS_bytes())
                        print(f"> TLS certificate sent to {client_port}.")
                        continue

                    elif "KEY_EXCHANGE" == id:
                        client_secret = request
                        if not client_secret:
                            print(f" > Failed to receive {client_port}'s public key")
                            try:
                                print(f' > Waiting 5 more seconds...')
                                client_secret = conn.recv(1024)
                            except socket.timeout as e:
                                print(f'   < socket {e}')
                            if not client_secret:
                                continue

                        my_secret = os.urandom(16)
                        conn.sendall(b'200 ' + my_secret)
                        print(f"> Sent server public key for Diffie-Hellman exchange to {client_port}")

                        shared_key = bytes(a ^ b for a, b in zip(my_secret, client_secret))
                        print(f" > Derived shared key for {client_port} ({shared_key})")
                        continue

                    elif "HTTPS_MESSAGE" == id:
                        encrypted_response = from_b64(request)
                        response = decrypt(encrypted_response, shared_key)
                        if not response:
                            print(f" > Empty message from {client_port}! Aborting connection.")
                            try:
                                print(f' > Waiting 5 more seconds...')
                                response = conn.recv(1024)
                            except socket.timeout as e:
                                print(f'   < socket {e}')
                            if not response:
                                continue
                        print(f"Received message from {client_port}: '{response}'")

                        identity = open(DATAFILE, 'r').read().strip()
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
            run_fake_server("localhost", 6665)
    except KeyboardInterrupt:
        print("\nFake server shutting down.")
