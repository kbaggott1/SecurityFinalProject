import secrets
class KeyGenerator:
    BYTE = 8
    def generate_key(block_size):
        key = secrets.token_bytes(block_size // KeyGenerator.BYTE)
        return key