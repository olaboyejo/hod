import sqlite3

with sqlite3.connect("sample.db") as connections:
    c = connections.cursor()
    c.execute ('''CREATE TABLE posts(title TEXT, description  TEXT)''')
    c.execute('INSERT INTO posts VALUES("Good", "I\'m good." )')
    c.execute('INSERT INTO posts VALUES("Well", "I\'m well.")')
