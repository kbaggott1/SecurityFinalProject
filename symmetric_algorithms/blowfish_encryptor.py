from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class BlowfishEncryptor:
    def __init__(self, key):
        self.key = key

    @staticmethod
    def generate_key(key_size=128):
        # Generate a random key of the specified size
        return get_random_bytes(key_size // 8)

    def encrypt(self, plaintext):
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC)
        padded_text = pad(plaintext.encode(), Blowfish.block_size)
        ciphertext = cipher.iv + cipher.encrypt(padded_text)
        return base64.b64encode(ciphertext).decode()

    def decrypt(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:Blowfish.block_size]
        ciphertext = ciphertext[Blowfish.block_size:]
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
        padded_text = cipher.decrypt(ciphertext)
        return unpad(padded_text, Blowfish.block_size).decode()
