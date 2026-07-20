from flask import Blueprint, request, jsonify
from store import get_db
bp = Blueprint("vuln86", __name__)

@bp.get("/vuln86/sorted")
def sorted_():
    col = request.args.get("col", "id")
    con = get_db(); cur = con.cursor()
    # VULN:VULN-86:CWE-89:taint SQL injection in an ORDER BY clause (non-quotable context)
    cur.execute("SELECT id, name, price FROM products ORDER BY " + col)
    rows = cur.fetchall(); con.close()
    return jsonify(rows)
