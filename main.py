#Imports
from symmetric_algorithms.des_encryptor import DESEncryptor
from symmetric_algorithms.aes_encryptor import AESEncryptor
from symmetric_algorithms.blowfish_encryptor import BlowfishEncryptor
try:
    from symmetric_algorithms.twofish_encryptor import TwofishEncryptor
except ModuleNotFoundError:
    print("Twofish module not found. Please install it using 'pip install twofish'")
from symmetric_algorithms.chacha20_encryptor import ChaCha20Encryptor
from symmetric_algorithms.cast_encryptor import CASTEncryptor
from asymmetric_algorithms.dsa_cryptor import DSACryptor
from asymmetric_algorithms.ecc_cryptor import ECCCryptor
from asymmetric_algorithms.rsa_encryptor import RSAEncryptor
from symmetric_algorithms.caesar_encryptor import CaesarEncryptor
from key_generator import KeyGenerator
import base64
import rsa

#DSA
def dsa_signing(text, signature = None, public_key = None, mode='sign'):
    if mode == 'sign':
        private_key, public_key = DSACryptor.generate_key_pair()

        print("Generated public key: " + public_key)

        signature = DSACryptor.sign_text(text, private_key)
        signature_as_text = base64.b64encode(signature).decode('utf-8')

        return signature_as_text, public_key
    
    elif mode == 'verify':
        signature = base64.b64decode(signature.encode('utf-8'))
        
        if DSACryptor.verify_text(text, signature, public_key):
            return "Text is valid and untampered.", None
        else:
            return "Text is invalid and may have been tampered with.", None

# ECC
def ecc_operations(text, signature = None, public_key = None, mode='sign'):
    if mode == 'sign':
        private_key, public_key = ECCCryptor.generate_key_pair()

        print("Generated public key: " + public_key)

        signature = ECCCryptor.sign_text(text, private_key)
        signature_as_text = base64.b64encode(signature).decode('utf-8')

        return signature_as_text, public_key
    
    elif mode == 'verify':
        signature = base64.b64decode(signature.encode('utf-8'))
        
        if ECCCryptor.verify_text(text, signature, public_key):
            return "Text is valid and untampered.", None
        else:
            return "Text is invalid and may be tampered with.", None


#CAST
def cast_encryption(text, key = None, mode='encrypt'):
    if mode == 'encrypt':
        key = KeyGenerator.generate_key(128)
        key_as_string = base64.b64encode(key).decode()
        print("Generated key: " + key_as_string)
        cast = CASTEncryptor(key)
        return cast.encrypt(text), key_as_string
    
    elif mode == 'decrypt':
        key = base64.b64decode(key.encode())
        cast = CASTEncryptor(key)
        return cast.decrypt(text), None

#ChaCha20
def chacha20_encryption(text, key = None, mode='encrypt'):
    if mode == 'encrypt':
        key = KeyGenerator.generate_key(256)
        key_as_string = base64.b64encode(key).decode()
        print("Generated key: " + key_as_string)
        chacha20 = ChaCha20Encryptor(key)
        return chacha20.encrypt(text), key_as_string
    
    elif mode == 'decrypt':
        key = base64.b64decode(input("Please enter key to decrypt: ").encode())
        nonce = base64.b64decode(input("Please enter nonce to decrypt: ").encode())
        chacha20 = ChaCha20Encryptor(key, nonce)
        return chacha20.decrypt(text)

#TwoFish
def twofish_encryption(text, key = None, mode='encrypt'):
    if mode == 'encrypt':
        key = KeyGenerator.generate_key(128)
        key_as_string = base64.b64encode(key).decode()
        print("Generated key: " + base64.b64encode(key).decode())
        twofish = TwofishEncryptor(key)
        return twofish.encrypt(text), key_as_string
    
    elif mode == 'decrypt':
        key = base64.b64decode(key.encode())
        twofish = TwofishEncryptor(key)
        return twofish.decrypt(text), None

#DES
def des_encryption(text, key = None, mode='encrypt'):
    if mode == 'encrypt':
        key = KeyGenerator.generate_key(64)
        key_as_string = base64.b64encode(key).decode()
        print("Generated key: " + key_as_string)
        des = DESEncryptor(key)
        return des.encrypt(text), key_as_string
    
    elif mode == 'decrypt':
        key = base64.b64decode(key.encode())
        des = DESEncryptor(key)
        return des.decrypt(text), None

#AES
def aes_encryption(text, key = None, mode='encrypt'):
    if mode == 'encrypt':
        key = KeyGenerator.generate_key(256)
        key_as_string = base64.b64encode(key).decode()
        print("Generated key: " + key_as_string)
        aes = AESEncryptor(key)
        return aes.encrypt(text), key_as_string
    
    elif mode == 'decrypt':
        key = base64.b64decode(key.encode())
        aes = AESEncryptor(key)
        return aes.decrypt(text), None

# Blowfish
def blowfish_encryption(text, key = None, mode='encrypt'):
    if mode == 'encrypt':
        key = BlowfishEncryptor.generate_key(128)
        key_as_string = base64.b64encode(key).decode()
        print("Generated key: " + key_as_string)
        blowfish = BlowfishEncryptor(key)
        return blowfish.encrypt(text), key_as_string
    
    elif mode == 'decrypt':
        key = base64.b64decode(key.encode())
        blowfish = BlowfishEncryptor(key)
        return blowfish.decrypt(text), None
    
# Caesar Cipher
def caesar_cipher(text, shift, mode='encrypt'):
    ce = CaesarEncryptor()
    if mode == 'encrypt':
        return ce.encrypt(text, shift)
    elif mode == 'decrypt':
        return ce.decrypt(text, shift)

# RSA
def rsa_encryption(text, public_key = None, mode='encrypt'):
    padding_start = '-----BEGIN RSA PUBLIC KEY-----'
    padding_end = '-----END RSA PUBLIC KEY-----'
    if mode == 'encrypt':
        if not public_key:
            public_key, private_key = RSAEncryptor.generate_key_pair()
            save_key_to_file(private_key)
            public_key_string = public_key.save_pkcs1('PEM').decode('utf-8').replace(padding_start, '').replace(padding_end, '')
        else:
            public_key_string = public_key
            public_key = padding_start + public_key + padding_end
            public_key = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'), format='PEM')
            
        return RSAEncryptor.encrypt(text, public_key), public_key_string
    elif mode == 'decrypt':
        private_key = load_key_from_file()
        plaintext = RSAEncryptor.decrypt(text, private_key)
        return plaintext, None

# RSA Helper functions
def save_key_to_file(key):
    with open("secrets", 'wb') as f:
        f.write(key.save_pkcs1('PEM'))

def load_key_from_file():
    with open("secrets", 'rb') as f:
        return rsa.PrivateKey.load_pkcs1(f.read(), format='PEM')

# Main Function
def main():
    print(f"""   _____                      _ _         
  / ____|                    (_) |        
 | (___   ___  ___ _   _ _ __ _| |_ _   _ 
  \___ \ / _ \/ __| | | | '__| | __| | | |
  ____) |  __/ (__| |_| | |  | | |_| |_| |
 |_____/ \___|\___|\__,_|_|  |_|\__|\__, |
                                     __/ |
                                    |___/ """)
    choice = input("Choose encryption method (Caesar, RSA, DES, AES, Blowfish, CAST5, ChaCha20, TwoFish, DSA, ECC): ").lower()

    if(choice == 'dsa' or choice == 'ecc'):
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
    elif choice == 'blowfish':
        result = blowfish_encryption(text, mode)
    elif choice == 'twofish':
        result = twofish_encryption(text, mode)
    elif choice == 'chacha20':
        result = chacha20_encryption(text, mode)
    elif choice == 'cast':
        result = cast_encryption(text, mode)
    elif choice == 'dsa':
        result = dsa_signing(text, mode)
    elif choice == 'ecc':
        result = ecc_operations(text, mode)
    
    print(f"Result: {result}")

if __name__ == "__main__":
    main()