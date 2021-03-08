#!/usr/bin/env python3

import sys
from base64 import *
from Crypto.Cipher import AES
from Crypto.Hash import *
from Crypto.Protocol.KDF import PBKDF2


chromiumCryptoSalt = b'saltysalt'
chromiumCryptoBitwidth = 128
chromiumCryptoIV = b' ' * int(chromiumCryptoBitwidth/8)
chromiumDefaultPassword = "peanuts"


def paddPlaintext(plaintext, blockSize):
    plaintextLength = len(plaintext)
    chrPlaintextLength = chr(plaintextLength)
    while len(plaintext) % blockSize != 0:
        plaintext += chrPlaintextLength
    return plaintext


def trimPlaintext(x):
    return x[:-x[-1]].decode('utf8')


def encryptAES128(plaintext, key):
    salt = chromiumCryptoSalt
    bits = chromiumCryptoBitwidth
    length = int(bits/8)
    iterations = 1
    pb_pass = key.encode("utf-8")
    key = PBKDF2(pb_pass, salt, length, iterations)

    iv = chromiumCryptoIV
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)

    success = False
    try:
        plaintext = paddPlaintext(plaintext, length)
        ciphertext = cipher.encrypt(plaintext)
        print("Password (encrypted): ", plaintext)
        success = True
    except:
        print("Error: An error occured during encryption.")

    return success, ciphertext


def decryptAES128(ciphertext, key):
    salt = chromiumCryptoSalt
    bits = chromiumCryptoBitwidth
    length = int(bits/8)
    iterations = 1
    pb_pass = key.encode("utf-8")
    key = PBKDF2(pb_pass, salt, length, iterations)

    iv = chromiumCryptoIV
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)

    success = False
    try:
        plaintext = cipher.decrypt(ciphertext)
        plaintext = trimPlaintext(plaintext)
        print("Password (decrypted): ", plaintext)
        success = True
    except:
        print("Error: An error occured during decryption.")

    return success, plaintext


def testCrypto():
    key = "randomXY/Z0123"
    password = "My&Password"
    ciphertext = encryptAES128(password, key)
    plaintext = decryptAES128(ciphertext, key)
    if plaintext == password:
        print("Crypto engine seems to work.")
    else:
        print("Crypto engine self-test failed. Aborting.")
        sys.exit(1)


def decryptDatabasePassword(encryptedPassword, keyringPassword):

    if len(encryptedPassword) < 3:
        print("Error: Password is too short.")
        return
    print("Password (encrypted): ", encryptedPassword)
    ciphertext = encryptedPassword[3:]

    if encryptedPassword[:3] == b"v10":
        key = chromiumDefaultPassword
        return decryptAES128(ciphertext, key)

    if encryptedPassword[:3] == b"v11":
        key = keyringPassword
        return decryptAES128(ciphertext, key)

    print("Error: Password entry is improperly formatted.")


def encryptPlaintextPassword(plaintext):
    key = chromiumDefaultPassword
    ciphertext = encryptAES128(plaintext, key)
    ciphertext = b"v10" + ciphertext
    print("Encrypted: ", plaintext, " -> ", ciphertext)
    return ciphertext
