from CertificateAuthority import CA, GlobalSign
from Utils import TLS_Certificate
import os
from datetime import datetime

def test_CA_Sign():

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

def test_SSL_Cert():
    # Certificate details for Microsoft (login.microsoft.com)
    subject = {
        "common_name": "login.microsoft.com",
        "organization": "Microsoft Corporation",
        "country": "US"
    }

    issuer = GlobalSign.to_issuer()

    serial_number = "987654321ABCDEF"
    not_before = datetime(2024, 1, 1)
    not_after = datetime(2025, 1, 1)

    # Create the TLS Certificate instance
    microsoft_cert = TLS_Certificate(
        subject=subject,
        issuer=issuer,
        serial_number=serial_number,
        signature=None,  # Signature will be generated by the CA
        not_before=not_before,
        not_after=not_after
    )

    # Convert certificate data to JSON format for signing
    cert_data = microsoft_cert.to_signable()

    # Sign the certificate data using GlobalSign CA's private key
    signature = GlobalSign.sign(cert_data)
    microsoft_cert.signature = signature.hex()  # Storing signature in hex format for readability

    # Print the signed certificate JSON
    print(microsoft_cert.to_json())

    # Optional: Save the certificate to a file
    microsoft_cert.save_to_file("microsoft_tls_certificate.json")

    # Verification step (example)
    is_valid = CA.authenticate(
        signed_data=signature,
        public_key=GlobalSign.get_pub(),
        expected_data=cert_data
    )
    print(f"Certificate authenticity verified: {is_valid}")

test_SSL_Cert()