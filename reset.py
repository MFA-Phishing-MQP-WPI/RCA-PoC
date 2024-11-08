import os
import shutil

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
                print(f"File '{file_path}' deleted successfully.")
            except Exception as e:
                print(f"\n\tError deleting file '{file_path}': {e}\n\n")
        # else:
            # print(f"File '{file_path}' does not exist.")

def delete_dirs(dirs):
    for dir_path in dirs:
        if os.path.isdir(dir_path):
            try:
                shutil.rmtree(dir_path)
                print(f"Directory '{dir_path}' deleted successfully.")
            except Exception as e:
                print(f"Error deleting directory '{dir_path}': {e}")
        # else:
            # print(f"Directory '{dir_path}' does not exist.")

if __name__ == "__main__":
    # Execute the deletions
    delete_files(FILES_TO_REMOVE)
    delete_dirs(DIRS_TO_REMOVE)
