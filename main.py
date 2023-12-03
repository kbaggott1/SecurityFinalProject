#Imports
from symmetric_algorithms.des_encryptor import DESEncryptor
from symmetric_algorithms.aes_encryptor import AESEncryptor
from symmetric_algorithms.camellia_encryptor import CamelliaEncryptor
try:
    from symmetric_algorithms.twofish_encryptor import TwofishEncryptor
except ModuleNotFoundError:
    print("Twofish module not found. Please install it using 'pip install twofish'")
from symmetric_algorithms.chacha20_encryptor import ChaCha20Encryptor
from symmetric_algorithms.cast_encryptor import CASTEncryptor
from asymmetric_algorithms.dsa_cryptor import DSACryptor
from asymmetric_algorithms.rsa_encryptor import RSAEncryptor
from symmetric_algorithms.caesar_encryptor import CaesarEncryptor
from key_generator import KeyGenerator
import os
import rsa

#DSA
def dsa_signing(text, mode='sign'):
    if mode == 'sign':
        private_key, public_key = DSACryptor.generate_key_pair()

        #print("Generated private key: " + private_key)
        print("Generated public key: " + public_key)

        signature = DSACryptor.sign_text(text, private_key)

        return "Signature: " + base64.b64encode(signature).decode('utf-8')
    
    elif mode == 'verify':
        public_key = input("Please enter key public key: ")
        signature = base64.b64decode(input("Please enter signature: ").encode('utf-8'))
        
        if DSACryptor.verify_text(text, signature, public_key):
            return "Text is valid and untampered."
        else:
            return "Text is invalid and may be tampered with."

#CAST
def cast_encryption(text, mode='encrypt'):
    if mode == 'encrypt':
        key = KeyGenerator.generate_key(128)
        print("Generated key: " + base64.b64encode(key).decode())
        cast = CASTEncryptor(key)
        return cast.encrypt(text)
    
    elif mode == 'decrypt':
        key = base64.b64decode(input("Please enter key to decrypt: ").encode())
        cast = CASTEncryptor(key)
        return cast.decrypt(text)

#ChaCha20
def chacha20_encryption(text, mode='encrypt'):
    if mode == 'encrypt':
        key = KeyGenerator.generate_key(256)
        print("Generated key: " + base64.b64encode(key).decode())
        chacha20 = ChaCha20Encryptor(key)
        return chacha20.encrypt(text)
    
    elif mode == 'decrypt':
        key = base64.b64decode(input("Please enter key to decrypt: ").encode())
        nonce = base64.b64decode(input("Please enter nonce to decrypt: ").encode())
        chacha20 = ChaCha20Encryptor(key, nonce)
        return chacha20.decrypt(text)

#TwoFish
def twofish_encryption(text, mode='encrypt'):
    if mode == 'encrypt':
        key = KeyGenerator.generate_key(128)
        print("Generated key: " + base64.b64encode(key).decode())
        twofish = TwofishEncryptor(key)
        return twofish.encrypt(text)
    
    elif mode == 'decrypt':
        key = base64.b64decode(input("Please enter key to decrypt: ").encode())
        twofish = TwofishEncryptor(key)
        return twofish.decrypt(text)

#DES
def des_encryption(text, mode='encrypt'):
    if mode == 'encrypt':
        key = KeyGenerator.generate_key(64)
        print("Generated key: " + base64.b64encode(key).decode())
        des = DESEncryptor(key)
        return des.encrypt(text)
    
    elif mode == 'decrypt':
        key = base64.b64decode(input("Please enter key to decrypt: ").encode())
        des = DESEncryptor(key)
        return des.decrypt(text)

#AES
def aes_encryption(text, mode='encrypt'):
    if mode == 'encrypt':
        key = KeyGenerator.generate_key(256)
        print("Generated key: " + base64.b64encode(key).decode())
        aes = AESEncryptor(key)
        return aes.encrypt(text)
    
    elif mode == 'decrypt':
        key = base64.b64decode(input("Please enter key to decrypt: ").encode())
        aes = AESEncryptor(key)
        return aes.decrypt(text)

#Camellia
def camellia_encryption(text, mode='encrypt'):
    if mode == 'encrypt':
        key = KeyGenerator.generate_key(256)
        print("Generated key: " + base64.b64encode(key).decode())
        camellia = CamelliaEncryptor(key)
        return camellia.encrypt(text)
    
    elif mode == 'decrypt':
        key = base64.b64decode(input("Please enter key to decrypt: ").encode())
        camellia = CamelliaEncryptor(key)
        return camellia.decrypt(text)
    
# Caesar Cipher
def caesar_cipher(text, shift, mode='encrypt'):
    ce = CaesarEncryptor()
    if mode == 'encrypt':
        return ce.encrypt(text, shift)
    elif mode == 'decrypt':
        return ce.decrypt(text, shift)

# RSA
def rsa_encryption(text, mode='encrypt'):
    if mode == 'encrypt':
        public_key, private_key = RSAEncryptor.generate_key_pair()
        print("Generated private key in secrets file.")
        save_key_to_file(private_key)
        return RSAEncryptor.encrypt(text, public_key)
    elif mode == 'decrypt':
        private_key = load_key_from_file()
        plaintext = RSAEncryptor.decrypt(text, private_key)
        return plaintext

# RSA Helper functions
def save_key_to_file(key):
    with open("secrets", 'wb') as f:
        f.write(key.save_pkcs1('PEM'))

def load_key_from_file():
    with open("secrets", 'rb') as f:
        return rsa.PrivateKey.load_pkcs1(f.read(), format='PEM')

# Main Function
def main():
    choice = input("Choose encryption method (Caesar, RSA, DES, AES, Camellia, CAST5, ChaCha20, TwoFish, DSA): ").lower()

    if(choice == 'dsa'):
        mode = input("Choose mode (sign/verify): ").lower()
    else:
        mode = input("Choose mode (encrypt/decrypt): ").lower()

    text = input("Enter text: ")

    if choice == 'caesar':
        shift = int(input("Enter shift value: "))
        result = caesar_cipher(text, shift, mode)
    elif choice == 'rsa':
        result = rsa_encryption(text, mode)
    elif choice == 'des':
        result = des_encryption(text, mode)
    elif choice == 'aes':
        result = aes_encryption(text, mode)
    elif choice == 'camellia':
        result = camellia_encryption(text, mode)
    elif choice == 'twofish':
        result = twofish_encryption(text, mode)
    elif choice == 'chacha20':
        result = chacha20_encryption(text, mode)
    elif choice == 'cast':
        result = cast_encryption(text, mode)
    elif choice == 'dsa':
        result = dsa_signing(text, mode)
    
    print(f"Result: {result}")

if __name__ == "__main__":
    main()