#!/usr/bin/env python3

import json
from random import randrange
from time import ctime as timestamp

import os
import shutil
import subprocess

import pyAesCrypt
from hashlib import sha256
from getpass import getpass


class PasswordVault:
    def __init__(self):
        print("\n---SESSION STARTED---")

        self.vault = {}         # usernames, passwords, salts, activity logs
        self.archive = []       # deleted users

        self._init_file()
        with open('vault.json', 'r') as f:
            vault_file = json.load(f)
            self.vault = vault_file['users']
            self.archive = vault_file['archive']

    def __str__(self):
        return str(self.vault)

    def _init_file(self):
        """Initialize the vault JSON file."""
        try:
            open('vault.json', 'r')
        except FileNotFoundError:
            self._write_file()

    def _write_file(self):
        """Write the current vault dict to the vault JSON file."""
        output_vault = {'users': self.vault, 'archive': self.archive}
        with open('vault.json', 'w') as f:
            json.dump(output_vault, f, indent=2)

    def get_action(self):
        """Prompt the user for surface level action."""
        print("\nWhat would you like to do?")
        print("\t(1) Sign up.")
        print("\t(2) Login.")
        print("\t(3) Change password.")
        print("\t(4) Delete account.")
        print("\t(5) Exit program.")

        action = input("Enter option number:\t")
        if action == '1':
            self.add_user()
            return True
        elif action == '2':
            self.authorize()
            return True
        elif action == '3':
            self.change_password()
            return True
        elif action == '4':
            self.delete_user()
            return True
        elif action == '5':
            subprocess.run("history -c", shell=True)
            print("\n---SESSION TERMINATED---\n")
            return False
        else:
            print("That is not a valid action. Please try again.")
            self.get_action()

    def add_user(self):
        """Add a user to the vault."""
        print("\nAdding user...")
        username = str(input("Choose a username:\t"))
        if username not in self.vault.keys():
            password = str(getpass("Choose a password:\t"))
            encrypted_password, salt = PasswordVault.encrypt(password)
            self.vault[username] = {}
            self.vault[username]['encrypted-password'] = encrypted_password
            self.vault[username]['salt'] = salt
            self.vault[username]['activity-log'] = [
                {
                    'activity': 'user-created',
                    'timestamp': timestamp()
                }
            ]
            self._write_file()
            print("Username and password added.")
        else:
            print("That username already exists.")

    def authorize(self):
        print("\nAuthorizing...")
        username = str(input("Username:\t"))
        if username in self.vault.keys():
            password = str(getpass("Password:\t"))
            encrypted_password = self.vault[username]['encrypted-password']
            salt = self.vault[username]['salt']
            if PasswordVault.check_password(password, encrypted_password, salt):
                self.vault[username]['activity-log'].append(
                    {
                        'activity': 'successful-authorization-attempt',
                        'timestamp': timestamp()
                    }
                )
                print("\n\t-AUTHORIZED-")
                self._write_file()
                secure_cont = True
                while secure_cont:
                    secure_cont = self.get_secure_action(username, password)
            else:
                self.vault[username]['activity-log'].append(
                    {
                        'activity': 'failed-authorization-attempt',
                        'timestamp': timestamp()
                    }
                )
                print("\n\t-NOT AUTHORIZED-")
                self._write_file()
        else:
            print("No user was found with that username. Please try again.")

    def get_secure_action(self, username, password):
        print("\nWhat would you like to do?")
        print("\t(1) Create a secure file.")
        print("\t(2) View a secure file.")
        print("\t(3) Add a line to a secure file.")
        print("\t(4) Exit secure area.")
        action = input("Enter option number:\t")
        if action == '1':
            self.create_secure_file(username, password)
            return True
        elif action == '2':
            self.view_secure_file(username, password)
            return True
        elif action == '3':
            self.edit_secure_file(username, password)
            return True
        elif action == '4':
            return False
        else:
            print("That is not a valid action. Please try again.")
            self.get_secure_action()

    @staticmethod
    def create_secure_file(username, password):
        if not os.path.exists('secure/{}'.format(username)):
            os.makedirs('secure/{}'.format(username))
        
        filename = input("Filename:\t")
        txt_path = 'secure/{}/{}'.format(username, filename)
        aes_path = 'secure/{}/{}.aes'.format(username, filename)
        open(txt_path, 'w')
        
        buffer = 64 * 1024  # AES encryption buffer size
        pyAesCrypt.encryptFile(txt_path, aes_path, password, buffer)
        os.remove(txt_path)

    @staticmethod
    def view_secure_file(username, password):
        filename = input("Filename:\t")
        txt_path = 'secure/{}/{}'.format(username, filename)
        aes_path = 'secure/{}/{}.aes'.format(username, filename)
        
        if not os.path.exists(aes_path):
            print('File does not exist.')
        else:
            buffer = 64 * 1024  # AES encryption buffer size
            pyAesCrypt.decryptFile(aes_path, txt_path, password, buffer)
            with open(txt_path, 'r') as f:
                print("\nFILE:<{}>".format(filename))
                lines = f.read().split('\n')
                for line in lines:
                    print(line)
            pyAesCrypt.encryptFile(txt_path, aes_path, password, buffer)
            os.remove(txt_path)

    @staticmethod
    def edit_secure_file(username, password):
        filename = input("Filename:\t")
        txt_path = 'secure/{}/{}'.format(username, filename)
        aes_path = 'secure/{}/{}.aes'.format(username, filename)
        
        if not os.path.exists(aes_path):
            print('File does not exist.')
        else:
            buffer = 64 * 1024  # AES encryption buffer size
            pyAesCrypt.decryptFile(aes_path, txt_path, password, buffer)
            text = input("Text to append to secure file:\n>> ") + "\n"
            with open(txt_path, 'a') as f:
                f.write(text)
            pyAesCrypt.encryptFile(txt_path, aes_path, password, buffer)
            os.remove(txt_path)

    def change_password(self):
        print("\nChanging password...")
        username = str(input("Username:\t"))
        if username in self.vault.keys():
            password = str(getpass("Old Password:\t"))
            encrypted_password = self.vault[username]['encrypted-password']
            salt = self.vault[username]['salt']
            if PasswordVault.check_password(password, encrypted_password, salt):
                password = str(getpass("New Password:\t"))
                encrypted_password, salt = PasswordVault.encrypt(password)
                self.vault[username]['encrypted-password'] = encrypted_password
                self.vault[username]['salt'] = salt
                self.vault[username]['activity-log'].append(
                    {
                        'activity': 'password-changed',
                        'timestamp': timestamp()
                    }
                )
                print("Password changed.")
            else:
                self.vault[username]['activity-log'].append(
                    {
                        'activity': 'failed-authorization-attempt',
                        'timestamp': timestamp()
                    }
                )
                print("\n\t-NOT AUTHORIZED-")
            self._write_file()
        else:
            print("No user was found with that username.")

    def delete_user(self):
        print("\nDeleting user...")
        print("Please enter your username and password to confirm.")
        username = str(input("Username:\t"))
        if username in self.vault.keys():
            password = str(getpass("Password:\t"))
            encrypted_password = self.vault[username]['encrypted-password']
            salt = self.vault[username]['salt']
            if PasswordVault.check_password(password, encrypted_password, salt):
                shutil.rmtree('secure/{}'.format(username))
                self.vault[username]['activity-log'].append(
                    {
                        'activity': 'user-deleted',
                        'timestamp': timestamp()
                    }
                )
                activity_log = self.vault[username]['activity-log'].copy()
                self.archive.append(
                    {
                        'username': username,
                        'activity-log': activity_log
                    }
                )
                del self.vault[username]
                print("User '{}' was deleted.".format(username))
            else:
                self.vault[username]['activity-log'].append(
                    {
                        'activity': 'failed-authorization-attempt',
                        'timestamp': timestamp()
                    }
                )
                print("\n\t-NOT AUTHORIZED-")
            self._write_file()
        else:
            print("No user was found with that username.")

    @staticmethod
    def encrypt(password, salt=None):
        if salt is None:
            salt = str(hex(randrange(1000000000000)))[2:]
        salted_password = password + salt
        encrypted_password = sha256(salted_password.encode('utf-8')).hexdigest()
        return encrypted_password, salt

    @staticmethod
    def check_password(test_password, encrypted_password, salt):
        encrypted_test_password, _ = PasswordVault.encrypt(test_password, salt)
        return encrypted_test_password == encrypted_password


if __name__ == '__main__':
    pv = PasswordVault()
    continuing = True
    while continuing:
        continuing = pv.get_action()
