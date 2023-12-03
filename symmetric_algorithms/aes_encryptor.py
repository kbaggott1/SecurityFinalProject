from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


class AESEncryptor:
    def __init__(self, key):
        self.key = key
        try:
            self.aes = AES.new(self.key, AES.MODE_ECB)
        except:
            print("AES Error: Invalid key")

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        ciphertext = self.aes.encrypt(pad(plaintext, AES.block_size))
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, ciphertext):
        try:
            if isinstance(ciphertext, str):
                ciphertext = base64.b64decode(ciphertext)

            plaintext = unpad(self.aes.decrypt(ciphertext), AES.block_size)

            if isinstance(plaintext, bytes):
                plaintext = plaintext.decode()
            return plaintext
        except Exception:
            return "AES Error: Invalid key or ciphertext"
