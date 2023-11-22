from cryptography.hazmat.primitives import padding
import base64
from twofish import Twofish

class TwofishEncryptor:
    def __init__(self, key):
        self.key = key
        self.twofish = Twofish(self.key)

    def __pad_text(text):
        padder = padding.PKCS7(128).padder()
        padded_text = padder.update(text.encode()) + padder.finalize()
        return padded_text
    
    def __unpad_text(padded_text):
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_text = unpadder.update(padded_text) + unpadder.finalize()
        return unpadded_text

    def encrypt(self, plaintext):
        padded_text = TwofishEncryptor.__pad_text(plaintext)
        ciphertext = self.twofish.encrypt(padded_text)
        encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')

        return encoded_ciphertext

    def decrypt(self, ciphertext):

        ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
        decrypted_text = self.twofish.decrypt(ciphertext)

        unpadded_text = TwofishEncryptor.__unpad_text(decrypted_text).decode()

        return unpadded_text