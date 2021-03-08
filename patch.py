#! /usr/bin/env python3
#
# Overwrites all broken passwords in a given database
# with the values of a backup database,
# if the backup passwords are intact.
# Lists all passwords, which are (still) broken.
#

import os
from database import *
from crypto import *


testCrypto(debug=True)

folder = "2021-03_chromium-password-recovery"
brokenDB = os.path.join(folder, "Login_Data.2021-03-08")
backupDB = os.path.join(folder, "Login_Data.2021-02-06")
keyringPasswordFilename = os.path.join(folder, "keyringPassword")

loginsBackup = databaseImportLogins(backupDB)
loginsBroken = databaseImportLogins(brokenDB)
keyringPassword = open(keyringPasswordFilename).read().strip()

#print(loginsBroken)
#print(loginsBackup)

#import sys
#sys.exit(0)

for url, user, encryptedPassword in loginsBackup:
    if len(url) == 0:
        print("Warning: Skipping empty database entry.")
        continue

    print(sepCount * "-")
    print("URL: {:s}\nUser: {:s}".format(url, user))

    success, plaintextBackup = decryptDatabasePassword(encryptedPassword, keyringPassword, debug=False)
    if success:
        print("Password decryption succeeded.")
    else:
        print("Password decryption failed. Skipping.")
        print(sepCount * "-")
        continue

    if hasEntry(loginsBroken, url, user):
        print("The broken database also has an entry for this URL and username:")
        brokenPassword = getPassword(loginsBroken, url, user)
        success, plaintextBroken = decryptDatabasePassword(brokenPassword, keyringPassword, debug=False)
        if success:
            print("Password decryption succeeded. Nothing to do here.")
        else:
            print("Password decryption failed. Good news: This password can be recovered.")

    print(sepCount * "-")
