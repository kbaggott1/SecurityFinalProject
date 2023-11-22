from Crypto.PublicKey import RSA
import base64
from des_encryptor import DESEncryptor
from twofish_encryptor import TwofishEncryptor
from key_generator import KeyGenerator
from chacha20_encryptor import ChaCha20Encryptor
from cast_encryptor import CASTEncryptor

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


# Caesar Cipher
def caesar_cipher(text, shift, mode='encrypt'):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if mode == 'encrypt':
            if char.isupper():
                result += chr((ord(char) + shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) + shift - 97) % 26 + 97)
        elif mode == 'decrypt':
            if char.isupper():
                result += chr((ord(char) - shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) - shift - 97) % 26 + 97)
    return result

# RSA Encryption/Decryption
def rsa_encryption(text, mode='encrypt'):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    if mode == 'encrypt':
        encryptor = RSA.import_key(public_key)
        encrypted = encryptor.encrypt(text.encode())
        return base64.b64encode(encrypted).decode()
    elif mode == 'decrypt':
        decryptor = RSA.import_key(private_key)
        decrypted = decryptor.decrypt(base64.b64decode(text))
        return decrypted.decode()

# Main Function
def main():
    choice = input("Choose encryption method (Caesar, RSA): ").lower()
    mode = input("Choose mode (encrypt/decrypt): ").lower()
    text = input("Enter text: ")

    if choice == 'caesar':
        shift = int(input("Enter shift value: "))
        result = caesar_cipher(text, shift, mode)
    elif choice == 'rsa':
        result = rsa_encryption(text, mode)
    elif choice == 'des':
        result = des_encryption(text, mode)
    elif choice == 'twofish':
        result = twofish_encryption(text, mode)
    elif choice == 'chacha20':
        result = chacha20_encryption(text, mode)
    elif choice == 'cast':
        result = cast_encryption(text, mode)
    
    print(f"Result: {result}")

if __name__ == "__main__":
    main()