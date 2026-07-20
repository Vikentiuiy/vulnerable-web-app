from flask import Blueprint, request, jsonify
from store import get_db
bp = Blueprint("vuln94", __name__)

@bp.get("/vuln94/bycat")
def bycat():
    ids = request.args.get("ids", "1")
    con = get_db(); cur = con.cursor()
    # VULN:VULN-94:CWE-89:taint SQL injection inside an IN (...) list
    cur.execute("SELECT id, name FROM products WHERE id IN (" + ids + ")")
    rows = cur.fetchall(); con.close()
    return jsonify(rows)
