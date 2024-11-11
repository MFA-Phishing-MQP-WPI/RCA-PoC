import os
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from MUtils import send, receive



DATAFILE:str = 'Data.txt'



def get_TLS_bytes() -> bytes:
    with open("microsoft_tls_certificate.json", "r") as f:
        return f.read().encode()



def run_microsoft_server(microsoft_host, microsoft_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((microsoft_host, microsoft_port))
        s.listen()
        print("Microsoft server listening...")
        while True:
            conn, addr = s.accept()
            with conn:
                conn.sendall(get_TLS_bytes())
                client_secret = conn.recv(1024)
                if not client_secret:
                    print(" > Failed to receive client public key")
                    print(' > restarting')
                    return
                my_secret = os.urandom(16)
                conn.sendall(my_secret)

                shared_key = bytes(a ^ b for a, b in zip(my_secret, client_secret))

                response = receive(conn, shared_key)
                if not response:
                    print(" > Received empty message from victim!")
                    print(' > restarting')
                    return
                print(f"Received message from victim: '{response}'\n")

                identity:str = open(DATAFILE, 'r').read()
                print(f" > Responding with '{identity}'")
                if send(identity, conn, shared_key):
                    print(" > Response sent successfully.")
                else:
                    print(" > Failed to send response!")
                    print(' > restarting')



if __name__ == "__main__":
    try:
        while True:
            run_microsoft_server("localhost", 6666)
    except KeyboardInterrupt:
        print("",end='\r')

