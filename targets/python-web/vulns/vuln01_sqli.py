from flask import Blueprint, request, jsonify
from store import get_db
bp = Blueprint("vuln01", __name__)

@bp.get("/vuln01/search")
def search():
    q = request.args.get("q", "")
    con = get_db()
    # VULN:VULN-01:CWE-89:taint SQL injection in product search (UNION extraction)
    rows = con.execute("SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'").fetchall()
    return jsonify([dict(r) for r in rows])
