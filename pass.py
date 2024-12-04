#!/bin/python3

import os   #import this for file handling
import base64 Used by fernet   
from cryptography.fernet import Fernet      #library for encrypting and decrypting  
import secrets  #both secret and  string generate password
import string
import json    #to store passwords in bytes or json file

# Generate or Load Encryption Key
def load_or_generate_key():    #defines the function , checks if an ecryption key exist, if not, generates one  and saves it
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
    else:
        with open("key.key", "rb") as key_file:
            key = key_file.read()
    return key

# Generate a secure password
def generate_password(length=12): #creates a randome password 
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

# Encrypt a password in ciphertext
def encrypt_password(password, fernet):
    return fernet.encrypt(password.encode()).decode()

# Decrypt a password to plaintext
def decrypt_password(encrypted_password, fernet):
    return fernet.decrypt(encrypted_password.encode()).decode()

# Save encrypted passwords to file
def save_password(account, encrypted_password):
    data = {}
    if os.path.exists("passwords.json"):
        with open("passwords.json", "r") as file:
            data = json.load(file)
    data[account] = encrypted_password
    with open("passwords.json", "w") as file:
        json.dump(data, file)

# Retrieve password for an account
def retrieve_password(account, fernet):
    if not os.path.exists("passwords.json"):
        return None
    with open("passwords.json", "r") as file:
        data = json.load(file)
    encrypted_password = data.get(account)
    if encrypted_password:
        return decrypt_password(encrypted_password, fernet)
    return None

# Main Program
# main program implements a menu driven cli for generating,storing, and retrieveing passwords
def main():
    key = load_or_generate_key()
    fernet = Fernet(key)

    while True:
        print("\n=== Password Manager ===")
        print("1. Generate Password")
        print("2. Add Password")
        print("3. Retrieve Password")
        print("4. Exit")
        choice = input("Select an option: ")

        if choice == "1":
            length = int(input("Enter password length: "))
            print("Generated Password:", generate_password(length))

        elif choice == "2":
            account = input("Enter account name: ")
            password = input("Enter password (or leave blank to generate): ")
            if not password:
                password = generate_password()
                print("Generated Password:", password)
            encrypted = encrypt_password(password, fernet)
            save_password(account, encrypted)
            print(f"Password for {account} saved successfully!")

        elif choice == "3":
            account = input("Enter account name: ")
            password = retrieve_password(account, fernet)
            if password:
                print(f"Password for {account}: {password}")
            else:
                print(f"No password found for {account}.")

        elif choice == "4":
            print("Exiting Password Manager.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

'''
CODE WORKING PRINCIPLE
1. gENERATE A STRONG PASSWORD
2. Encrypt  and store passwords
3. Retrieve and decryot  the password when needed

--How it works---
1 .  the encryption key management first checks if there is akready a key saved in a file key.key
2. if the key doesn't exist, it generates  a new one useing Fernet and saves it
3. The key critical for encryption and decryption
4. The manager generates random strong passowrds with mi=x of letters ,nos and symbols
5. You can set length of the code generate one
6. Fernet converts passwrds to cipher text
7. json stores it as passwords.json 
8. When retrieved , the json file is called up and decrypted 
9. The program is simple just
a --  Generate passwords
b --  Save passowrds  for accounts
C  -- Retrieve passwords
d -- Exit the program
-- it is a symmetric encyption format, one key for encrypt and decrypt
'''
