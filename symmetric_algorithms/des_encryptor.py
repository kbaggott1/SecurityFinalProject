from cryptography.hazmat.primitives import padding
from Crypto.Cipher import DES
import base64

class DESEncryptor:
    def __init__(self, key, mode = DES.MODE_ECB):
        self.key = key
        self.des = DES.new(self.key, mode)

    def __pad_text(text):
        padder = padding.PKCS7(64).padder()
        padded_text = padder.update(text.encode()) + padder.finalize()
        return padded_text
    
    def __unpad_text(padded_text):
        unpadder = padding.PKCS7(64).unpadder()
        unpadded_text = unpadder.update(padded_text) + unpadder.finalize()
        return unpadded_text

    def encrypt(self, text):
        padded_text = DESEncryptor.__pad_text(text)
        ciphertext = self.des.encrypt(padded_text)

        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, text): 
        ciphertext = base64.b64decode(text.encode('utf-8'))
        decrypted_text = self.des.decrypt(ciphertext)
        unpadded_text = DESEncryptor.__unpad_text(decrypted_text)
        
        return unpadded_text.decode('utf-8')