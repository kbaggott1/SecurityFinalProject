import rsa
import base64

class RSAEncryptor:
    @staticmethod
    def generate_key_pair(key_size=2048):
        public_key, private_key = rsa.newkeys(key_size)
        return public_key, private_key

    @staticmethod
    def encrypt(text, public_key):
        encrypted = rsa.encrypt(text.encode(), public_key)
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def decrypt(ciphertext, private_key):
        encrypted = base64.b64decode(ciphertext.encode())
        return rsa.decrypt(encrypted, private_key).decode()
