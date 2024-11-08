import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from FileReader import FR

class CA:
    _private_key = None
    _public_key = None
    _private_key_file = "ca_private_key.pem"
    _public_key_file = "ca_public_key.pem"

    def __init__(self, name: str, organization: str, country: str = "US"):
        self.name: str = name
        self.organization: str = organization
        self.country: str = country
        self._private_keyy = None
        self._public_key = None
        self._private_key_file: str = f"{self.name}/private_key.pem"
        self._public_key_file: str = f"{self.name}/public_key.pem"
        self._initialize_ca()

    def _initialize_ca(self):
        if FR.path.exists(self._private_key_file):
            key_data = FR.read(self._private_key_file, mode="rb")
            self._private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
            self._public_key = self._private_key.public_key()
        else:
            self._generate_keys()

    def to_issuer(self) -> dict:
        return {
            "common_name": self.name,
            "organization": self.organization,
            "country": self.country
        }

    def _generate_keys(self):
        """Generates a new RSA key pair and saves them to files."""
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()

        # Write the private key to a file
        FR.write(
            self._private_key_file, 
            self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ),
            mode="wb"
        )

        # Write the public key to a file
        FR.write(
            self._public_key_file,
            self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ), 
            mode="wb"
        )

    def sign(self, data: bytes) -> bytes:
        """Signs data using the private key and returns the base64-encoded signature."""
        if self._private_key is None:
            self._initialize_ca()
        signature = self._private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def get_pub(self) -> bytes:
        """Returns the public key in PEM format."""
        if self._public_key is None:
            self._initialize_ca()
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def authenticate(signed_data: bytes, public_key: bytes, expected_data: bytes = None) -> bool:
        """Authenticates by verifying that signed_data matches expected_data using the public key."""
        try:
            # Load the public key from PEM format
            pub_key = serialization.load_pem_public_key(
                public_key,
                backend=default_backend()
            )

            # Verify the signature
            pub_key.verify(
                signed_data,
                expected_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


GlobalSign: CA = CA('GlobalSignCA', "GlobalSign CA Ltd.")
IdenTrust: CA = CA('IdenTrustCA', "IdenTrust CA Ltd.")
