import socket
import json
from VUtils import TLS_Certificate, cert_is_authentic, send, receive
import os

# Access Point Shell host and port
AP_HOST = "localhost"
AP_PORT = 7777  # Port for the Access Point Shell

def query_dns(dns_host, dns_port, to: str = "login.microsoft.com"):
    """
    Sends a DNS request through the Access Point Shell (acting as a proxy).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Connect to the Access Point Shell instead of DNS directly
            s.connect((dns_host, dns_port))
            s.sendall(to.encode())  # Request the DNS resolution for the target
            
            # Attempt to receive and decode the response as UTF-8
            response = s.recv(1024)
            
            try:
                port = int(response.decode('utf-8').strip())  # Decode and parse as integer
                return port
            except UnicodeDecodeError:
                # Handle case where response is binary
                print("Received binary data, attempting fallback handling.")
                port = int.from_bytes(response, "big")  # Interpret as big-endian integer
                return port
    except ConnectionRefusedError:
        print("\n\tCould not connect to Access Point. Is it running?\n")
        exit()
    except ValueError:
        print("\n\tReceived unexpected data format. Check DNS response.\n")
        exit()

def connect_to_web_service(host, port, target: str = 'login.microsoft.com'):
    """
    Connects to the Microsoft service through the Access Point Shell (acting as a proxy).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # Connect to the Access Point Shell instead of Microsoft directly
            s.connect((host, port))
        except ConnectionRefusedError:
            print(f"\n\tCould not connect to web_service({target} at {port}). Is it running?\n")
            exit()
        
        # Step 1: Receive the SSL certificate (simulated)
        cert_data = s.recv(4096).decode()  # Receive the JSON data of the certificate
        cert_dict = json.loads(cert_data)
        
        # Re-create TLS_Certificate instance from received data
        received_certificate = TLS_Certificate(
            subject=cert_dict["subject"],
            issuer=cert_dict["issuer"],
            serial_number=cert_dict["serial_number"],
            signature=cert_dict["signature"],
            not_before=cert_dict["validity_period"]["not_before"],
            not_after=cert_dict["validity_period"]["not_after"]
        )

        # Step 2: Verify certificate authenticity
        if cert_is_authentic(received_certificate.get_signature(), received_certificate.get_expected_data()):
            print("SSL Certificate successfully verified.")
        else:
            print("SSL Certificate authenticity could not be verified. (HTTPS FAILED) Aborting.")
            return

        # Step 3: Perform Diffie-Hellman key exchange
        my_secret = os.urandom(16)
        s.sendall(my_secret)
        their_secret = s.recv(1024)

        # Create shared key for symmetric encryption
        shared_key = bytes(a ^ b for a, b in zip(my_secret, their_secret))

        # Step 4: Send and receive messages over the secure channel
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
        # Use Access Point Shell as the intermediary for DNS resolution
        dns_port = query_dns(AP_HOST, AP_PORT, to=target)
        if dns_port == -1:
            print(f"DNS could not find {target}")
            exit()
        # Use Access Point Shell as the intermediary for connecting to Microsoft
        connect_to_web_service(AP_HOST, dns_port, target=target)
    except KeyboardInterrupt:
        print("", end='\r')
