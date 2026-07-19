from flask import Blueprint, request, jsonify
from store import get_db
bp = Blueprint("vuln12", __name__)

@bp.get("/vuln12/account")
def account():
    uid = request.args.get("id", "1")
    con = get_db()
    # VULN:VULN-12:CWE-639:logic IDOR — no authorization check tying the session to id
    row = con.execute("SELECT id, username, role FROM users WHERE id = ?", (uid,)).fetchone()
    return jsonify(dict(row) if row else {})
