from flask import Blueprint, request, jsonify
from store import get_db
bp = Blueprint("vuln92", __name__)

@bp.get("/vuln92/find")
def find():
    name = request.args.get("name", "")
    con = get_db(); cur = con.cursor()
    # VULN:VULN-92:CWE-89:taint SQL injection inside a LIKE pattern
    cur.execute("SELECT id, username, role FROM users WHERE username LIKE '" + name + "%'")
    rows = cur.fetchall(); con.close()
    return jsonify(rows)
