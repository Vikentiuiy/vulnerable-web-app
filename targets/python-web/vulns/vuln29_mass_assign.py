import hashlib
from flask import Blueprint, request, jsonify
from store import get_db
bp = Blueprint("vuln29", __name__)

@bp.post("/vuln29/register")
def register():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    role = request.form.get("role", "user")
    con = get_db()
    # VULN:VULN-29:CWE-915:logic mass assignment — caller-controlled role bound directly
    con.execute("INSERT INTO users(username,password,role,bio,ssn) VALUES(?,?,?,'','000-00-0000')",
                (u, hashlib.md5(p.encode()).hexdigest(), role))
    con.commit()
    return jsonify({"status": "registered", "role": role})
