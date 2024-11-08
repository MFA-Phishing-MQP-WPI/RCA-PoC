from CertificateAuthority import CA, GlobalSign
import os

microsoft_file = 'Microsoft_SSL_Cert'
microsoft_name = b'login.microsoft.com'

vm_file = 'VM_SSL_Cert'
vm_name = b'vm.com'

signature_file = vm_file
data = vm_name

# Check if signature file exists
if os.path.exists(signature_file):
    # Read the signature from the file (read as binary)
    with open(signature_file, 'rb') as f:
        signature = f.read()
else:
    # Sign the data and save the signature in base64 encoding
    signature = GlobalSign.sign(data)
    with open(signature_file, 'wb') as f:
        f.write(signature)

# Retrieve the public key
public_key = GlobalSign.get_pub()

# Verify the signature
is_valid = CA.authenticate(signature, public_key, expected_data=data)
print(f"Signature valid: {is_valid}")

with open(signature_file, 'rb') as f:
        sig = f.read()
