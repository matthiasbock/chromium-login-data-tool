#!/usr/bin/env python3

import sqlite3


def databaseImportLogins(filename):
    conn = sqlite3.connect(filename)
    cursor = conn.cursor()
    data = cursor.execute('SELECT action_url, username_value, password_value FROM logins;').fetchall()
    #result = []
    #for url, user, password in data:
    #   result += [(url, user, password)]
    conn.close()
    return data


def databaseUpdatePassword(filename, url=None, user=None, encryptedPassword=None, debug=False):
    if url is None:
        print("Error: URL cannot be None. Skipping database update.")
        return False
    if user is None:
        print("Error: User may be an empty string, but not None. Skipping database update.")
        return False
    if encryptedPassword is None:
        print("Error: Password may be an empty string, but not None. Skipping database update.")
        return False
    conn = sqlite3.connect(filename)
    cursor = conn.cursor()
    where = 'WHERE action_url="{:s}" AND username_value="{:s}"'.format(url, user)
    value = "SET password_value=?"
    sql = "UPDATE logins {:s} {:s};".format(value, where)
    if debug:
        print(sql)
    success = False
    data = cursor.execute(sql, [encryptedPassword])
    sql = "SELECT password_value FROM logins {:s} AND password_value=?".format(where)
    if debug:
        print(sql)
    data = cursor.execute(sql, [encryptedPassword]).fetchall()
    if len(data) == 1:
        success = True
    conn.commit()
    conn.close()
    return success


def getPassword(loginList, url, user):
    for _url, _user, _password in loginList:
        if (_url == url) and (_user == user):
            return _password
    return None, None, None


def hasEntry(loginList, url, user):
    for _url, _user, _password in loginList:
        if (_url == url) and (_user == user):
            return True
    return False
