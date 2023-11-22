from cryptography.hazmat.primitives import padding
from Crypto.Cipher import ChaCha20
import base64

class ChaCha20Encryptor:

    def __init__(self, key, nonce = None):
        self.key = key
        self.chacha20 = ChaCha20.new(key = self.key, nonce = nonce)

    def __pad_text(text):
        padder = padding.PKCS7(64).padder()
        padded_text = padder.update(text.encode('utf-8')) + padder.finalize()
        return padded_text
    
    def __unpad_text(padded_text):
        unpadder = padding.PKCS7(64).unpadder()
        unpadded_text = unpadder.update(padded_text) + unpadder.finalize()
        return unpadded_text

    def encrypt(self, text):
        padded_text = ChaCha20Encryptor.__pad_text(text)
        ciphertext = self.chacha20.encrypt(padded_text)

        return "Encrypted text: " + base64.b64encode(ciphertext).decode('utf-8') + " Nonce: " + base64.b64encode(self.chacha20.nonce).decode('utf-8')

    def decrypt(self, text): 
        ciphertext = base64.b64decode(text.encode('utf-8'))
        decrypted_text = self.chacha20.decrypt(ciphertext)
        unpadded_text = ChaCha20Encryptor.__unpad_text(decrypted_text)
        
        return unpadded_text.decode('utf-8')
    