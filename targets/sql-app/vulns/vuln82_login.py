from flask import Blueprint, request, jsonify
from store import get_db

bp = Blueprint("vuln82", __name__)


@bp.post("/vuln82/login")
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    con = get_db()
    cur = con.cursor()
    # VULN:VULN-82:CWE-89:taint SQL injection in authentication (login bypass)
    cur.execute("SELECT username, role FROM users WHERE username = '" + u + "' AND password = MD5('" + p + "')")
    row = cur.fetchone()
    con.close()
    return jsonify({"status": "ok", "user": row[0]} if row else {"status": "invalid"})
