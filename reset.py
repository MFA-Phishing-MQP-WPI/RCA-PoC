import os
import shutil
import psutil
import sys

# List of files and directories to remove
FILES_TO_REMOVE = [
    'Microsoft_SSL_Cert', 'VM_SSL_Cert', 'CA_gen', 'ca_private_key.pem', 'ca_public_key.pem', 'tls_certificate.json', 
    'microsoft_tls_certificate.json'
]
DIRS_TO_REMOVE  = ['GlobalSignCA', 'IdenTrustCA']

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



def clean_and_delete(arg: str):
    if arg in ['p', 'ports', 'a', 'all']:
        ports_to_cleanup = [5555, 6666, 6665]
        cleanup_ports(ports_to_cleanup)
    if arg in ['f', 'files', 'a', 'all']:
        delete_files(FILES_TO_REMOVE)
        delete_dirs(DIRS_TO_REMOVE)

def miss_used():
    print("ERROR INCORRECT USAGE")
    print("USAGE: python3 reset.py [(P)orts (F)iles (A)ll]")
    exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1].lower() not in ['p', 'ports', 'f', 'files', 'a', 'all']:
        miss_used()
    clean_and_delete(sys.argv[1].lower())
