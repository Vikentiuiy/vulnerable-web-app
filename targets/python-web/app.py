import importlib
import pkgutil
import sqlite3

from flask import Flask, jsonify

import vulns
from harness import detector
from harness.tracker import TRACKER
from store import DB, get_db


def seed():
    con = get_db()
    c = con.cursor()
    # VULN:VULN-19:CWE-256:config passwords stored as unsalted MD5
    # VULN:VULN-20:CWE-312:config secret_answer kept in cleartext
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT,
        secret_answer TEXT, role TEXT DEFAULT 'user', bio TEXT, ssn TEXT)""")
    c.execute("CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price REAL)")
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        c.executemany("INSERT INTO users(username,password,secret_answer,role,bio,ssn) VALUES(?,?,?,?,?,?)", [
            ("admin", "0192023a7bbd73250516f069df18b500", "my-first-car", "admin", "Site administrator", "111-22-3333"),
            ("alice", "7c6a180b36896a0a8c02787eeafb0e4c", "fluffy", "user", "Hi, I am Alice", "222-33-4444")])
        c.executemany("INSERT INTO products(name,price) VALUES(?,?)", [("Laptop", 999.0), ("Keyboard", 49.0)])
    con.commit()
    con.close()


def create_app():
    app = Flask(__name__)
    app.config["DB"] = DB
    seed()
    # auto-register one blueprint per vuln module (1:1)
    for mod in pkgutil.iter_modules(vulns.__path__):
        m = importlib.import_module(f"vulns.{mod.name}")
        if hasattr(m, "bp"):
            app.register_blueprint(m.bp)
    detector.install(app)

    @app.get("/api/status")
    def status():
        return jsonify(TRACKER.snapshot())

    @app.get("/")
    def index():
        # VULN:VULN-35:CWE-1021:config no X-Frame-Options / CSP frame-ancestors set anywhere -> clickjacking
        return {"app": "vuln-python-web", "vulns": len(TRACKER.states), "dashboard": "/api/status"}

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082)
