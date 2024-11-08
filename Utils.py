import json
from datetime import datetime

class TLS_Certificate:
    def __init__(self, subject, issuer, serial_number, signature, not_before, not_after):
        # Initialize the certificate components
        self.subject = subject
        self.issuer = issuer
        self.serial_number = serial_number
        self.signature = signature
        self.validity_period = {
            "not_before": not_before,
            "not_after": not_after
        }

    def to_json(self):
        # Convert the certificate to a JSON string
        return json.dumps(self.__dict__, default=str, indent=4)

    def to_signable(self) -> bytes:
        return self.to_json().encode('utf-8')

    def save_to_file(self, filename):
        # Save the certificate JSON to a file
        try:
            with open(filename, 'w') as file:
                file.write(self.to_json())
            print(f"Certificate saved to {filename}")
        except Exception as e:
            print(f"Error saving certificate to file: {e}")


def Test_TSL_Certificate():
    # Sample certificate details
    subject = {
        "common_name": "www.example.com",
        "organization": "Example Inc.",
        "country": "US"
    }
    issuer = {
        "common_name": "Example CA",
        "organization": "Example CA Ltd.",
        "country": "US"
    }
    serial_number = "123456789ABCDEF"
    signature = "abc123signatureXYZ"
    not_before = datetime(2024, 1, 1)
    not_after = datetime(2025, 1, 1)

    # Create a TLS certificate instance
    cert = TLS_Certificate(subject, issuer, serial_number, signature, not_before, not_after)
    
    # Print the certificate in JSON format
    print(cert.to_json())

    # Save the certificate to a file
    cert.save_to_file("tls_certificate.json")

Test_TSL_Certificate()
