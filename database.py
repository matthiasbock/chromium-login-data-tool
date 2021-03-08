#!/usr/bin/env python3

import sqlite3


def databaseImportLogins(filename):
    conn = sqlite3.connect(filename)
    cursor = conn.cursor()
    data = cursor.execute('SELECT action_url, username_value, password_value FROM logins')
    return data


def databaseUpdatePassword(filename, url=None, user=None, encryptedPassword=None):
    conn = sqlite3.connect(filename)
    cursor = conn.cursor()
    data = cursor.execute('UPDATE logins WHERE ... TODO SET password_value=...')


def getLogin(loginList, url, user):
    for _url, _user, _password in loginList:
        if (_url == url) and (_user == user):
            return _url, _user, _password
    return None, None, None


def hasEntry(loginList, url, user):
    for _url, _user, _password in loginList:
        if (_url == url) and (_user == user):
            return True
    return False
