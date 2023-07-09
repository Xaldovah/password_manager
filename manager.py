#!/usr/bin/python3
"""
Password Manager Program
"""

import os.path
from cryptography.fernet import Fernet


KEY_FILE = "key.key"
PASSWORDS_FILE = "passwords.txt"


def write_key():
    """
    Generate a new encryption key and write it to a file.
    """
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)


def load_key():
    """
    Load the encryption key from a file, or generate a new key if the file doesn't exist.
    """
    if not os.path.exists(KEY_FILE):
        write_key()

    with open(KEY_FILE, "rb") as key_file:
        key = key_file.read()
    return key


def view():
    """
    View the existing passwords stored in the passwords file.
    """
    master_pwd = input("Enter the master password to view passwords: ")
    if validate_master_password(master_pwd):
        with open(PASSWORDS_FILE, "r") as f:
            for line in f.readlines():
                data = line.rstrip()
                user, passwd = data.split("|")
                decrypted_passwd = fer.decrypt(passwd.encode()).decode()
                print(f"User: {user}, Password: {decrypted_passwd}")
    else:
        print("Invalid master password. Access denied.")


def add():
    """
    Add a new password to the passwords file.
    """
    name = input("Account Name: ")
    pwd = input("Password: ")

    with open(PASSWORDS_FILE, "a") as f:
        encrypted_pwd = fer.encrypt(pwd.encode()).decode()
        f.write(f"{name}|{encrypted_pwd}\n")


def validate_master_password(pwd):
    """
    Validate the master password provided.
    """
    return pwd == master_pwd


master_pwd = input("What is the master password? ")
key = load_key()
fer = Fernet(key)

while True:
    mode = input("Would you like to add a new password or view existing ones (view, add), press q to quit: ").lower()
    if mode == "q":
        break
    elif mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print("Invalid input")
        continue

