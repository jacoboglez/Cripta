#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Cripta
Encryption (password protection) system for files.

It requires the following pip installable packages:
· docopt (argument parsing): https://github.com/docopt/docopt
· cryptography: https://cryptography.io/en/latest/

Usage:
  cripta.py encrypt <files> ... [--copy]
  cripta.py decrypt <files> ... [--copy]
  cripta.py (-h | --help)
  cripta.py --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  -c --copy     Preserves the original encrypted or unencrypted files.

"""

from docopt import docopt
import os
from pathlib import Path
import base64
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken


def keygen(password):
    '''Generates a Fernet object derived from the password
    given to the function that will be later used to encrypt the 
    contents of the files.
    '''

    # Convert string password to bytecode
    password = password.encode()

    # Salt needs to be stored in order to decrypt the message with the same key
    # salt = os.urandom(16)
    salt = b'_salt_'

    # Hashed password generator -> key generator
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))

    # return Fernet object that encrypts/decrypts with the key
    return Fernet(key)


def convert_file(mode, input_file, password, copy=False):
    ''' Encrypt or decrypt a file given a password and the path to the file.

    Args:
        mode ('encrypt' or 'decrypt'):  action to perform to the file
        input_file (str): path of the file to encrypt or decrypt
        password (str): password to encrypt or decrypt the file
        output_file (str, path): path file to generate 
            (default is to overwrite the original file)
        copy (bool): flag that preserves the original file if True (default False)
    '''

    # Generation of the Fernet object with the key
    # associated with the password
    key = keygen(password)

    # Encryption of the file data
    with open(input_file, 'rb') as f:
        data = f.read()

    # Encrypt or decrypt the data
    if mode.lower() == 'encrypt':
        modified_data = key.encrypt(data)
        output_file = input_file.with_suffix(input_file.suffix + '.cri')
    elif mode.lower() == 'decrypt': 
        try:
            modified_data = key.decrypt(data)
        except InvalidToken:
            raise PermissionError('Incorrect password.')
        output_file = input_file.stem
    else:
        raise ValueError("Expected 'encrypt' or 'decrypt'.")

    # Write to output file
    with open(output_file, 'wb') as f:
        f.write(modified_data)

    # Delete origin file (if not overwritten by the encrypted file)
    if not copy:
        os.remove(input_file)
    

def getpassword():
    '''Ask for a password and check that the given password 
    was correct by asking again.
    Loops until a couple of passwords agree and returns it.
    '''

    while True:
        password1 = getpass('Please, introduce the password:')
        password2 = getpass('Verify your password:')

        if password1 == password2:
            return password1
        print('Incorrect password, try again.')


def main(arguments):
    if arguments['encrypt']:
        action = 'encrypt'
    elif arguments['decrypt']:
        action = 'decrypt'
    else:
        raise NotImplementedError('Command not implemented.')

    password = getpassword()

    for f in arguments['<files>']:
        input_file = Path(f)
        if os.path.exists(input_file):
            input_file = Path(f)
            print(action)
            convert_file(action, input_file, password, copy=arguments['--copy'])
        else:
            raise NameError('File not found.')


if __name__ == '__main__':
    arguments = docopt(__doc__, version='Cripta 0.1')
    main(arguments)
