from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

class DSACryptor:

    def generate_key_pair():
        private_key = dsa.generate_private_key(key_size=2048)
        public_key = private_key.public_key()
        
        private_key_str = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_key_str = base64.b64encode(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode('utf-8')

        
        return private_key_str, public_key_str
    
    def __string_to_private_key(private_key_str):
        private_key = serialization.load_pem_private_key(
            private_key_str.encode('utf-8'),
            None,
            backend=default_backend()
        )
        return private_key
    
    def __string_to_public_key(public_key_str):
        public_key = serialization.load_pem_public_key(
            base64.b64decode(public_key_str),
            backend=default_backend()
        )
        return public_key
    
    def sign_text(text, private_key_str):
        private_key = DSACryptor.__string_to_private_key(private_key_str)

        signature = private_key.sign(text.encode('utf-8'), hashes.SHA256())
        return signature
    
    def verify_text(text, signature, public_key_str):
        public_key = DSACryptor.__string_to_public_key(public_key_str)

        try:
            public_key.verify(signature, text.encode('utf-8'), hashes.SHA256())
            return True
        except:
            return False
        
