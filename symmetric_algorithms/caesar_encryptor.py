#Imports

'''
Caesar Cipher encrypts and decrypts by shifting each character of the message
by a certain number of letters back or forth
'''
class CaesarEncryptor:
	
		def __init__(self):
				pass

		'''
		Encrypts the passed text with the shift and returns it.
		parameters:
			text: str -> the message to be encrypted
			shift: int = 0 -> offset to encrypt the message by
		returns:
			str -> the encrypted message
		'''
		def encrypt(self, text: str, shift: int = 0) -> str:
				result = ""
				#Get remainder of shift if it's over alphabet size
				if shift < 0:
						shift = shift % -26
				else:
					shift = shift % 26
				for character in text:
					if character.isalpha():
						result += chr(ord(character)+shift)
					else:
						result += character
				return result

		'''
		Decrypts the passed encrypted text with the shift and returns it
		parameters:
			text: str -> the encrypted message to be decrypted
			shift: int = 0 -> offset used to encrypt/decrypt the message
		returns: 
			str -> the decrypted message
		'''
		def decrypt(self, text:str, shift: int = 0) -> str:
					result = ""
					if shift < 0:
							shift = shift % -26
					else:
						shift = shift % 26
					for character in text:
						if character.isalpha():
							result += chr(ord(character)-shift)
						else:
							result += character
					return result


#For testing
if __name__ == "__main__":
	ce = CaesarEncryptor()
	encryptedText = ce.encrypt("Hello", -1)
	print(encryptedText)
	decryptedText = ce.decrypt(encryptedText, -1)
	print(decryptedText)
	
