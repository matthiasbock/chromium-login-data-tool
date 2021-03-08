#!/usr/bin/env python3

import sys
from base64 import *
from Crypto.Cipher import AES
from Crypto.Hash import *
from Crypto.Protocol.KDF import PBKDF2


sepCount = 130

chromiumCryptoSalt = b'saltysalt'
chromiumCryptoBitwidth = 128
chromiumCryptoIV = b' ' * int(chromiumCryptoBitwidth/8)
chromiumMasterPassword = "peanuts"


def paddPlaintext(plaintext, blockSize, debug=False):
    length = len(plaintext)
    num = blockSize - (length % blockSize)
    if debug:
        print("Padding: Plaintext size is {:d}, chiffre block size is {:d}, padding {:d} bytes to get {:d} bytes.".format(length, blockSize, num, length+num))
    padding = num * chr(num)
    plaintext += padding
    return plaintext.encode("utf-8")


def trimPlaintext(x, debug=False):
    trimCount = x[-1]
    if debug:
        print("Password (untrimmed): ", x)
    if trimCount > len(x):
        trimCount = 0
    if debug:
        print("Will trim {:d} trailing bytes.".format(trimCount))
    y = x[:-trimCount]
    if debug:
        print("Password (trimmed):   ", y)
    s = y.decode('utf8')
    if debug:
        print("Password (decoded):   ", s)
    return s


def encryptAES(plaintext, password, debug=False):
    salt = chromiumCryptoSalt
    bits = chromiumCryptoBitwidth
    length = int(bits/8)
    iterations = 1
    pb_pass = password.encode("utf-8")
    key = PBKDF2(pb_pass, salt, length, iterations)

    iv = chromiumCryptoIV
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)

    success = False
    ciphertext = None
    try:
        if debug:
            print("Password (plaintext): ", plaintext)
        plaintext = paddPlaintext(plaintext, length, debug=False)
        if debug:
            print("Password (padded):    ", plaintext)
        ciphertext = cipher.encrypt(plaintext)
        if debug:
            print("Password (encrypted): ", ciphertext)
        success = True
    except:
        if debug:
            print("Error: An error occured during encryption.")

    return success, ciphertext


def decryptAES(ciphertext, password, debug=False):
    salt = chromiumCryptoSalt
    bits = chromiumCryptoBitwidth
    length = int(bits/8)
    iterations = 1
    pb_pass = password.encode("utf-8")
    key = PBKDF2(pb_pass, salt, length, iterations)

    iv = chromiumCryptoIV
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)

    success = False
    plaintext = None
    try:
        if debug:
            print("Password (encrypted): ", ciphertext)
        plaintext = cipher.decrypt(ciphertext)
        if debug:
            print("Password (decrypted): ", plaintext)
        plaintext = trimPlaintext(plaintext, debug=False)
        if debug:
            print("Password (trimmed):   ", plaintext)
        success = True
    except:
        print("Error: An error occured during decryption.")

    return success, plaintext


def testCrypto(debug=False):
    if debug:
        print(sepCount * "-")
        print("Testing encryption / decryption:")
    testData = "randomXY/Z01234"
    password = "My&Password"
    encryptionSuccess, ciphertext = encryptAES(testData, password, debug=debug)
    decryptionSuccess, plaintext  = decryptAES(ciphertext, password, debug=debug)
    if plaintext == testData:
        if debug:
            print("Crypto engine seems to work.")
            print(sepCount * "-")
    else:
        print("Fatal: Crypto self-test failed. Aborting.")
        if debug:
            print(sepCount * "-")
        sys.exit(1)


def decryptDatabasePassword(encryptedPassword, keyringPassword, debug=False):

    if len(encryptedPassword) < 3:
        print("Error: Password is too short.")
        return

    if debug:
        print("Password (encrypted): ", encryptedPassword)
    ciphertext = encryptedPassword[3:]

    success = None
    plaintext = None

    if encryptedPassword[:3] == b"v10":
        password = chromiumMasterPassword
        success, plaintext = decryptAES(ciphertext, password, debug=debug)

    if encryptedPassword[:3] == b"v11":
        password = keyringPassword
        success, plaintext = decryptAES(ciphertext, password, debug=debug)

    if success is None:
        print("Error: Failed to detect encryption method (unsupported method?)")
        success = False

    if success:
        # Run additional checks
        if len(plaintext) < 3:
            # That's awfully short. Assume that something went wrong.
            success = False
        else:
            # Decrypted data must not begin with an encrypted database entry prefix.
            prefix = plaintext[:2]
            if (prefix == "v8") or (prefix == "v9"):
                print("Error: Decrypted password is apparently still encrypted.")
                success = False
            prefix = plaintext[:3]
            if (prefix == "v10") or (prefix == "v11"):
                print("Error: Decrypted password is apparently still encrypted.")
                success = False
            # A password can only consist of printable characters.
            trailing = plaintext[3:]
            if not trailing.isprintable():
                print("Error: Non-printable characters in password.")
                success = False

    return success, plaintext


def encryptPlaintextPassword(plaintext):
    password = chromiumMasterPassword
    success, ciphertext = encryptAES(plaintext, password)
    if success:
        ciphertext = b"v10" + ciphertext
        if debug:
            print("Encrypted: ", plaintext, " -> ", ciphertext)
    else:
        print("Error: Encryption failed.")
    return success, ciphertext
