from flask import Blueprint, request, jsonify
from store import get_db
bp = Blueprint("vuln88", __name__)

@bp.get("/vuln88/product")
def product():
    pid = request.args.get("id", "1")
    con = get_db(); cur = con.cursor()
    # VULN:VULN-88:CWE-89:taint SQL injection in a numeric context (no quotes around the value)
    cur.execute("SELECT id, name, price FROM products WHERE id = " + pid)
    rows = cur.fetchall(); con.close()
    return jsonify(rows)
