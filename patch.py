#! /usr/bin/env python3
#
# Overwrites all broken passwords in a given database
# with the values of a backup database,
# if the backup passwords are intact.
# Lists all passwords, which are (still) broken.
#

import sys, os, shutil
from database import *
from crypto import *


# Perform a crypto self-test
if not testCrypto(debug=False):
    print("Can't work without functional crypto engine. Aborting.")
    sys.exit(1)

# Files and folders
folder = "2021-03_chromium-password-recovery"
brokenDB = os.path.join(folder, "Login_Data.2021-03-08")
backupDB = os.path.join(folder, "Login_Data.2021-02-06")
restoredDB = os.path.join(folder, "recovery.db")
keyringPasswordFilename = os.path.join(folder, "keyringPassword")

# Data
loginsBackup = databaseImportLogins(backupDB)
loginsBroken = databaseImportLogins(brokenDB)
if not os.path.exists(restoredDB):
    shutil.copyfile(brokenDB, restoredDB)
keyringPassword = open(keyringPasswordFilename).read().strip()

# Statistics
countSkipped = 0
countProcessed = 0
countNoAction = 0
countRestored = 0
countUnsuccessful = 0

# Process data
for url, user, encryptedPassword in loginsBackup:
    if len(url) == 0:
        print("Warning: Skipping empty database entry.")
        countSkipped += 1
        continue

    countProcessed += 1
    print(sepCount * "-")
    print("URL: {:s}\nUser: {:s}".format(url, user))

    if not hasEntry(loginsBroken, url, user):
        print("The broken database has no password saved for this URL and username. Skipping.")
        print(sepCount * "-")
        countUnsuccessful += 1
        continue

    print("Decrypting password from backup database ... ")
    success, plaintextBackup = decryptDatabasePassword(encryptedPassword, keyringPassword, debug=False)
    if not success:
        print("Failed. Skipping.")
        print(sepCount * "-")
        countUnsuccessful += 1
        continue

    print("Success.")

    print("Decrypting password from current database ... ")
    brokenPassword = getPassword(loginsBroken, url, user)
    success, plaintextBroken = decryptDatabasePassword(brokenPassword, keyringPassword, debug=False)
    if success:
        print("Success.")
        if plaintextBackup == plaintextBroken:
            print("The two passwords are identical.")
        else:
            print("Current password: {:s}".format(plaintextBroken))
            print("Backup password: {:s}".format(plaintextBackup))
            print("Warning: The two password do not match! No action is taken here.")
        countNoAction += 1
    else:
        print("Failed.")
        print("Restoring password from backup ...") #" {:s}".format(plaintextBackup))
        success, recryptedPassword = encryptPlaintextPassword(plaintextBackup, debug=False)
        if success:
            success = databaseUpdatePassword(restoredDB, url, user, recryptedPassword, debug=False)
            if success:
                print("Success.")
                countRestored += 1
            else:
                print("For some reason the database update has failed.")
                countUnsuccessful += 1
        else:
            countUnsuccessful += 1

    print(sepCount * "-")

# Print Statistics
print("Statistics:")
print("Processed: {:d}".format(countProcessed))
print("Skipped: {:d}".format(countSkipped))
print("No action taken: {:d}".format(countNoAction))
print("Restored: {:d}".format(countRestored))
print("Unsuccessful: {:d}".format(countUnsuccessful))
print(sepCount * "-")
