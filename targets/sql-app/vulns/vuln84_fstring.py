from flask import Blueprint, request, jsonify
from store import get_db

bp = Blueprint("vuln84", __name__)


@bp.get("/vuln84/byname")
def byname():
    name = request.args.get("name", "")
    con = get_db()
    cur = con.cursor()
    # VULN:VULN-84:CWE-89:taint SQL injection — f-string interpolation of HTTP input into a query
    cur.execute(f"SELECT id, username, role FROM users WHERE username = '{name}'")
    rows = cur.fetchall()
    con.close()
    return jsonify(rows)
