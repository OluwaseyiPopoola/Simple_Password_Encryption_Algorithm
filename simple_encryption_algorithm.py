def main():
    pass_word = input("Enter a password to encrypt: ")
    password_manager = SimpleEncryption(pass_word)

    # Encrypt the password
    encrypted_password = password_manager.encrypt()
    print(f"Encrypted password: {encrypted_password}")

    # Decrypt the password
    decrypted_password = password_manager.decrypt(encrypted_password)
    print(f"Decrypted password: {decrypted_password}")

class SimpleEncryption:
    def __init__(self, password):
        self.password = password
        self.size = len(password)

    def encrypt(self):
        encrypted = ''.join(chr(ord(char) + self.size) for char in self.password)
        return encrypted

    def decrypt(self, encrypted_password):
        decrypted = ''.join(chr(ord(char) - self.size) for char in encrypted_password)
        return decrypted
    
if __name__ == "__main__":
    main()