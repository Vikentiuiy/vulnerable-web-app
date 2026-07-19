import hashlib
from flask import Blueprint, request, jsonify
from store import get_db
bp = Blueprint("vuln02", __name__)

@bp.post("/vuln02/login")
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    h = hashlib.md5(p.encode()).hexdigest()
    con = get_db()
    # VULN:VULN-02:CWE-89:taint SQL injection in authentication (login bypass)
    row = con.execute("SELECT username, role FROM users WHERE username = '" + u + "' AND password = '" + h + "'").fetchone()
    return jsonify({"status": "ok", "user": row["username"]} if row else {"status": "invalid"})
