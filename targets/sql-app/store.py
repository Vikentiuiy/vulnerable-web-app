import os
import time

import mysql.connector


def get_db():
    for _ in range(30):
        try:
            return mysql.connector.connect(
                host=os.environ.get("DB_HOST", "db"),
                user="root", password="root", database="vulnsql")
        except Exception:
            time.sleep(2)
    raise RuntimeError("db unavailable")
