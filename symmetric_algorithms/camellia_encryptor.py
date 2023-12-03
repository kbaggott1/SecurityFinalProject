try:
    import camellia
except:
    print("Camellia module not found. Please install it using 'pip install python-camellia'")
import os


'''
!!!Needs pip install python-camellia to work, which needs pip install cffi. need to test
if it works on lab computers. otherwise need a new algo since this one is not supported
with any native python packages!!!
'''
class CamelliaEncryptor:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        cipher = camellia.new(self.key, camellia.MODE_CBC, IV=os.urandom(16))
        padded_plaintext = self._pad(plaintext)
        encrypted_text = cipher.encrypt(padded_plaintext)
        return cipher.IV + encrypted_text

    def decrypt(self, encrypted_text):
        iv = encrypted_text[:16]  # First 16 bytes for IV
        cipher = camellia.new(self.key, camellia.MODE_CBC, IV=iv)
        decrypted_padded_text = cipher.decrypt(encrypted_text[16:])
        return self._unpad(decrypted_padded_text)

    def _pad(self, s):
        return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

    def _unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]
