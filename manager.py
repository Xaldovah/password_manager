#!/usr/bin/python3

import os.path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import base64


KEYS_DIRECTORY = "keys"
PASSWORDS_FILE = "passwords.txt"
ITERATIONS = 100_000
KEY_LENGTH = 32

master_passwords = {}


def generate_key(master_password, salt):
    """
    Generate a unique encryption key for a given master password and salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        salt=salt,
        length=KEY_LENGTH,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key)


def load_key(master_password, salt):
    """
    Load the encryption key for a given master password and salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        salt=salt,
        length=KEY_LENGTH,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key)


def write_key(user, master_password, key, salt):
    """
    Write the encryption key to a file and update the master password dictionary.
    """
    key_file = os.path.join(KEYS_DIRECTORY, f"{user}.key")
    os.makedirs(os.path.dirname(key_file), exist_ok=True)
    with open(key_file, "wb") as f:
        f.write(key)

    global master_passwords
    if user in master_passwords:
        master_passwords[user].append(master_password)
    else:
        master_passwords[user] = [master_password]

    with open(PASSWORDS_FILE, "a") as f:
        f.write(f"{user}|{master_password}|{base64.urlsafe_b64encode(salt).decode()}\n")


def add():
    """
    Add a new password to the passwords file.
    """
    name = input("Account Name: ")
    pwd = input("Password: ")
    user = input("Enter your username: ")

    master_pwd = input("Enter your master password: ")
    salt = os.urandom(KEY_LENGTH)
    key = generate_key(master_pwd, salt)
    write_key(user, master_pwd, key, salt)

    cipher_suite = Fernet(key)
    encrypted_pwd = cipher_suite.encrypt(pwd.encode()).decode()

    with open(PASSWORDS_FILE, "a") as f:
        f.write(f"{user}|{name}|{encrypted_pwd}|{base64.urlsafe_b64encode(salt).decode()}\n")


def view():
    """
    View the existing passwords stored in the passwords file.
    """
    user = input("Enter your username: ")

    if user not in master_passwords:
        print("Invalid username. Access denied.")
        return

    master_pwd = input("Enter the master password to view passwords: ")

    if master_pwd not in master_passwords[user]:
        print("Invalid master password. Access denied.")
        return

    key_file = os.path.join(KEYS_DIRECTORY, f"{user}.key")
    if not os.path.exists(key_file):
        print("No passwords found.")
        return

    with open(key_file, "rb") as f:
        key = f.read()

    with open(PASSWORDS_FILE, "r") as f:
        for line in f.readlines():
            values = line.strip().split("|")
            if len(values) == 4 and values[0] == user:
                cipher_suite = Fernet(key)
                try:
                    decrypted_passwd = cipher_suite.decrypt(values[2].encode()).decode()
                    print(f"User: {values[0]}, Account: {values[1]}, Password: {decrypted_passwd}")
                except InvalidToken:
                    print("Invalid master password. Access denied.")
                    return


def read_passwords_file():
    """
    Read the passwords file and populate the master_passwords dictionary.
    """
    global master_passwords
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, "r") as f:
            for line in f.readlines():
                values = line.strip().split("|")
                if len(values) == 3:
                    user, master_pwd, salt = values
                    salt = base64.urlsafe_b64decode(salt.encode())
                    if user in master_passwords:
                        master_passwords[user].append(master_pwd)
                    else:
                        master_passwords[user] = [master_pwd]


read_passwords_file()

while True:
    mode = input("Press Add or View (to add or view passwords), press q to quit: ").lower()
    if mode == "q":
        break
    elif mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print("Invalid input")
        continue
