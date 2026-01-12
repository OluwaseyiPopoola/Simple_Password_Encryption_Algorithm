def main():
    pass_word = input("Enter a password to encrypt: ")
    password_manager = SimpleEncryption(pass_word)

    # Encrypt the password
    encrypted_password = password_manager.encrypt()
    print(f"Encrypted password: {encrypted_password}")
    print()
    # Decrypt the password
    decrypted_password = password_manager.decrypt(encrypted_password)
    print(f"Decrypted password: {decrypted_password}")

class SimpleEncryption:
    def __init__(self, password):
        self.password = password
        self.size = len(password)

    def encrypt(self):
        # encrypted = ''.join(chr(ord(char)^self.size + self.size) for char in self.password)
        encrypted = []
        for i in range(len(self.password)):
            encrypted_char = chr((ord(self.password[i]) + i) ^ (i + self.size))
            encrypted.append(encrypted_char)
            print(f"Encrypting char '{self.password[i]} : {ord(self.password[i])}' to '{encrypted_char} : {ord(encrypted_char)}'")
        return "".join(encrypted)

    def decrypt(self, encrypted_password):
        # decrypted = ''.join(chr((ord(char)^i) - i) for char in encrypted_password)
        decrypted = []
        for i in range(len(encrypted_password)):
            decrypted_char = chr((ord(encrypted_password[i]) ^ (i + self.size)) - i)
            decrypted.append(decrypted_char)
            print(f"Decrypting char '{encrypted_password[i]} : {ord(encrypted_password[i])}' to '{decrypted_char} : {ord(decrypted_char)}'")
        return "".join(decrypted)

if __name__ == "__main__":
    main()