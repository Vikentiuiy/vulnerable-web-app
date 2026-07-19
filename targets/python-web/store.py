import sqlite3

DB = "/app/vuln.db"


def get_db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con
