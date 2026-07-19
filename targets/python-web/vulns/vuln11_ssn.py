from flask import Blueprint, request, jsonify
from store import get_db
bp = Blueprint("vuln11", __name__)

@bp.get("/vuln11/profile")
def profile():
    uid = request.args.get("id", "1")
    con = get_db()
    row = con.execute("SELECT username, ssn FROM users WHERE id = ?", (uid,)).fetchone()
    # VULN:VULN-11:CWE-200:logic sensitive data (SSN) returned to any caller
    return jsonify({"username": row["username"], "ssn": row["ssn"]} if row else {})
