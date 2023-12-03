from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

class ECCCryptor:

    @staticmethod
    def generate_key_pair():
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        
        private_key_str = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_key_str = base64.b64encode(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode('utf-8')

        return private_key_str, public_key_str
    
    @staticmethod
    def __string_to_private_key(private_key_str):
        private_key = serialization.load_pem_private_key(
            private_key_str.encode('utf-8'),
            None,
            backend=default_backend()
        )
        return private_key
    
    @staticmethod
    def __string_to_public_key(public_key_str):
        public_key = serialization.load_pem_public_key(
            base64.b64decode(public_key_str),
            backend=default_backend()
        )
        return public_key
    
    @staticmethod
    def sign_text(text, private_key_str):
        private_key = ECCCryptor.__string_to_private_key(private_key_str)
        signature = private_key.sign(text.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
        return signature
    
    @staticmethod
    def verify_text(text, signature, public_key_str):
        public_key = ECCCryptor.__string_to_public_key(public_key_str)
        try:
            public_key.verify(signature, text.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
            return True
        except:
            return False
