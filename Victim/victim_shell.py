import socket
import json
from VUtils import TLS_Certificate, TLS_is_authentic, cas_display, encrypt, decrypt, to_b64, is_verbose, \
    edit_verbose, known_CA_names, refresh_CAs, display_CAs, download_progress, installing, FR
import os

# Access Point Shell host and port
AP_HOST = "localhost"
AP_PORT = 7777  # Port for the Access Point Shell
TIME_OUT_TIME = 5.0

def query_dns(dns_host, dns_port, to: str = "login.microsoft.com"):
    """
    Sends a DNS request through the Access Point Shell (acting as a proxy).
    """
    try:
        print(f"\n > Asking DNS to resolve {to}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((dns_host, dns_port))
            
            # Send the DNS request with target port (5555 for DNS) and specify 1 expected response
            dns_request = f"{5555} {to} 1"
            s.sendall(dns_request.encode())
            
            response = s.recv(1024).decode('utf-8').strip()
            status_code, message = response.split(" ", 1)
            # b_status_code, b_message = response[:3], response[4:]
            # status_code = b_status_code.decode()
            # message = b_message.encode()

            if status_code == "200":
                try:
                    port = int(message)
                    print(f"   < DNS resolved {to} to {port}")
                    return port
                except ValueError:
                    if is_verbose(): print(f"   < Received non-integer port from DNS: '{message}'")
                    return -1
            elif status_code == '402':
                if is_verbose(): print('\n\tDNS refused to connect.')
                return -1
            elif status_code == "404":
                if is_verbose(): print("\n\tDNS returned 'Not Found'.")
                return -1
            else:
                if is_verbose(): print(f"   < Unexpected status code {status_code} from DNS.")
                return -1
    except ConnectionRefusedError as e:
        if is_verbose(): print(f"   < Wi-Fi Access Point cannot be reached")
        print('\n\tErr Check Wi-Fi Access Point\n')
        exit()
    except Exception as e:
        if is_verbose(): print(f"   < Unexpected error in query_dns: {e}")
        return -1

def connect_to_web_service_via_ap(ap_host, ap_port, target_port, target: str = 'login.microsoft.com'):
    """
    Connects to the Microsoft service through the Access Point Shell, requesting the Access Point
    to act on the victim's behalf.
    """
    try:
        print(f'\n > Connecting to {target} at {target_port} via Access Point')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ap_host, ap_port))
            s.settimeout(TIME_OUT_TIME)
            request_message = f"{target_port} CERT_REQUEST 1"  # Specify 1 response expected from Microsoft (the TLS certificate)
            if is_verbose(): print('')
            print(f'  >> Requesting {target} TLS Certification via Access Point')
            s.sendall(request_message.encode())
        
            # Step 1: Receive the TLS certificate
            response = s.recv(4096)
            status_code = response[:3].decode('utf-8')
            
            if status_code != "200":
                if is_verbose(): print(f"   < Failed to connect to {target}. Status code: {status_code}")
                return
            if is_verbose(): print(f'   < Receved response with status code: {status_code}; reading certificate ...')
            
            try:
                cert_data = response[3:].decode('utf-8').strip()
            except ValueError as e:
                if is_verbose(): print(f'   < Certificate is not formatted correctly. (HTTPS FAILED) Aborting connection with unauthorised web-server.')
                return
            
            if is_verbose(): print(f'     | Verifying authenticity of the recieved certificate ...')
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
            is_valid:bool = TLS_is_authentic(received_certificate, target)
            if is_verbose(): 
                if is_valid:
                    print(f'     | Verification success - using known CAs [{cas_display()}]')
                else:
                    print(f'     | Verification failure - using known CAs [{cas_display()}]')

            if is_valid: # cert_is_authentic(received_certificate.get_signature(), received_certificate.get_expected_data()):
                print("   < TLS Certificate successfully verified.")
            else:
                print("   < TLS Certificate authenticity could not be verified. (HTTPS FAILED) Aborting connection with unauthorised web-server.")
                return

            # Step 3: Perform Diffie-Hellman key exchange
            if is_verbose(): print('')
            print(f'  >> Requesting public key exchange to begin HTTPS (Diffie-Hellman)')
            my_secret: bytes = os.urandom(16)
            s.sendall(f"{target_port} <flag: key_exchange>".encode() + my_secret + " 1".encode())
            
            response: bytes = s.recv(1024)
            response_code, their_secret = response[:3].decode(), response[4:]
            if response_code != '200':
                if is_verbose(): print(f'   < Got response code {response_code} instead of 200 when waiting to recieve their secret')
                if is_verbose(): print(f'     HTTPS failed. Aborting connection')
                exit()
            # print(f' << DEBUG: {their_secret=} >>')
            if not their_secret:
                if is_verbose(): print("   < Failed to receive server's public key.")
                return

            shared_key = bytes(a ^ b for a, b in zip(my_secret, their_secret))
            if is_verbose(): print(f"   < Derived shared key: {shared_key}")

            # Step 4: Send and receive messages over the secure channel
            # send("This is the victim, announce yourself!", s, shared_key, target_port=target_port)
            s.sendall(f"{target_port} <flag: https_msg>".encode() + to_b64(encrypt("This is the victim, announce yourself!", shared_key)) + " 1".encode())
            # microsoft_response = receive(s, shared_key)[0]
            response = s.recv(1024)
            response_code, encrypted_microsoft_response = response[:3].decode(), response[4:]
            if response_code != '200':
                if is_verbose(): print(f'   < Got response code {response_code} instead of 200 when waiting to recieve their response')
                if is_verbose(): print(f'     HTTPS pipe broken. Aborting connection')
                exit()

            microsoft_response = decrypt(encrypted_microsoft_response, shared_key)

            print(f"   < Microsoft says: '{microsoft_response}'")
    except socket.timeout as e:
        if is_verbose(): print(f'   < socket {e} (5 seconds have passed with no response from (R)WAP)')
    except Exception as e:
        if is_verbose(): print(f"   < Unexpected error in connect_to_web_service_via_ap: {e}")

def download_ca(APh, APp):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((APh, APp))
        try:
            s.sendall(b'download certificate')
            response = s.recv(2048)
            download_progress(4, 'Downloading Certificate ')
        except Exception as e:
            print(f' > err {e}')
            return
    FR.write('RootCertificates/MaliciousCA_public_key.pem', response, mode='wb')
    print(' > Download Successful')
    installing(2.6)
    refresh_CAs()
    if is_verbose(): display_CAs()
    print(' > CAs Updated\n')

    
def connect_request() -> bytes:
    if 'MaliciousCA' not in known_CA_names():
        return b'connection request'
    return b'infected connection request'

def connect_to_wifi_access_point(APh, APp):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((APh, APp))
        try:
            s.sendall(connect_request())
            response = s.recv(1024).decode()
        except Exception as e:
            print(f' > err {e}')
            exit()
    if response == '200 approved':
        print(" > connected to WiFi successfully")
        return
    if response == '403 certificate missing':
        print(" > Can't connect to WiFi, reason: 'certificate missing'")
        if input('   Download CA from WiFi? (Y/n) > ').lower() not in ['yes', 'y']:
            exit()
        download_ca(APh, APp)
        if input('   Try reconnect to WiFi? (Y/n) > ').lower() not in ['yes', 'y']:
            exit()
        connect_to_wifi_access_point(APh, APp)


def connect(target):
    print('No internet ...')
    print('Connecting to WiFi ...')
    connect_to_wifi_access_point(AP_HOST, AP_PORT)
    print(f'\nInitiating connection to {target}')
    dns_port = query_dns(AP_HOST, AP_PORT, to=target)
    if dns_port == -1:
        exit()
    connect_to_web_service_via_ap(AP_HOST, AP_PORT, target_port=dns_port, target=target)

if __name__ == "__main__":
    edit_verbose()
    try:
        connect('login.microsoft.com')
    except KeyboardInterrupt:
        print("\nVictim shell shutting down.")
    except Exception as e:
        if is_verbose(): print(f"Unexpected error: {e}")
