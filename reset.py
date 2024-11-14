import os
import shutil
import psutil
import sys
from typing import Tuple

# List of files and directories to remove
FILES_TO_REMOVE = [
    'Microsoft_SSL_Cert', 'VM_SSL_Cert', 'CA_gen', 'ca_private_key.pem', 'ca_public_key.pem', 'tls_certificate.json', 
    'microsoft_tls_certificate.json'
]
DIRS_TO_REMOVE  = ['GlobalSignCA', 'IdenTrustCA']
VICTIM_ROOT_CAS_FILEPATH: str = 'Victim/RootCertificates/MaliciousCA_public_key.pem'


def reset_victim_Root_Certs(disp:bool=True):
    try:
        if os.path.exists(VICTIM_ROOT_CAS_FILEPATH):
            os.remove(VICTIM_ROOT_CAS_FILEPATH)
            print(f' > File "{VICTIM_ROOT_CAS_FILEPATH}" deleted successfully.')
            if disp: print('    > Victim CAs Reset')
    except Exception:
        pass

def delete_files(files):
    for file_path in files:
        if os.path.isfile(file_path):
            try:
                os.remove(file_path)
                print(f" > File '{file_path}' deleted successfully.")
            except Exception as e:
                print(f"\n !\tError deleting file '{file_path}': {e}\n\n")
        # else:
            # print(f"File '{file_path}' does not exist.")

def delete_dirs(dirs):
    for dir_path in dirs:
        if os.path.isdir(dir_path):
            try:
                shutil.rmtree(dir_path)
                print(f" > Directory '{dir_path}' deleted successfully.")
            except Exception as e:
                print(f"\n !\tError deleting directory '{dir_path}': {e}\n\n")
        # else:
            # print(f"Directory '{dir_path}' does not exist.")

def cleanup_ports(ports):
    for conn in psutil.net_connections():
        if conn.laddr.port in ports:
            process = psutil.Process(conn.pid)
            print(f" > Terminating process {process.pid} on port {conn.laddr.port}")
            process.terminate()
            process.wait()  # Wait for the process to terminate
    # print("Ports cleaned up.")



def clean_and_delete(arg: str, debug:bool=False):
    if arg in ['p', 'ports', 'a', 'all']:
        if debug: print(" - ports - ")
        ports_to_cleanup = [5555, 6666, 6665, 7777]
        cleanup_ports(ports_to_cleanup)
    if arg in ['f', 'files', 'a', 'all']:
        if debug: print(" - files - ")
        delete_files(FILES_TO_REMOVE)
        delete_dirs(DIRS_TO_REMOVE)
        reset_victim_Root_Certs()

def miss_used():
    print("\nERROR INCORRECT USAGE")
    print("\n\tUSAGE: python3 reset.py")
    print("\t\tTo reset the victim's Root Certificates")
    print("\n\tUSAGE: python3 reset.py   [ (P)orts  (F)iles  (A)ll ]   [ OPTIONAL:  -(D)bug ]\n")
    print("\t\tReset Ports: (p / ports)")
    print("\t\t\tWill close any running processes on saved ports in case a process ends unexpectedly")
    print("\t\tReset Files: (f / files)")
    print("\t\t\tWill remove files used to setup the PoC like the CAs and local TLS Certificates")
    print("\t\t\tWill also remove malicious certificates from the Vicitm (use python3 reset.py instead)")
    print("\t\tReset All: (a / all)")
    print("\t\t\tWill run both `ports` and `files`\n")
    exit()

def process_args() -> Tuple[bool, str, bool]:
    if len(sys.argv) not in [2, 3]:
        return (False, "", False)
    index = -1
    if len(sys.argv) == 3:
        arg1, arg2 = sys.argv[1].lower(), sys.argv[2].lower()
        if arg1 not in ['-d', '-debug'] and arg2 not in ['-d', '-debug']:
            return (False, "", False)
        index = 2 if arg1 in ['-d', '-debug'] else 1
        if sys.argv[index].lower() not in ['p', 'ports', 'f', 'files', 'a', 'all']:
            return (False, "", False)
        return (True, sys.argv[index].lower(), True)
    if sys.argv[1].lower() not in ['p', 'ports', 'f', 'files', 'a', 'all']:
        return (False, "", False)
    return (True, sys.argv[1].lower(), False)
    

if __name__ == "__main__":
    if len(sys.argv) == 1:
        reset_victim_Root_Certs(disp=False)
        exit()
    correct_usage, action, debug = process_args()
    if not correct_usage:
        miss_used()
    clean_and_delete(action, debug=debug)
