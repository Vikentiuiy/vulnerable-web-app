from flask import Blueprint, request, jsonify
from store import get_db

bp = Blueprint("vuln81", __name__)


@bp.get("/vuln81/search")
def search():
    q = request.args.get("q", "")
    con = get_db()
    cur = con.cursor()
    # VULN:VULN-81:CWE-89:taint SQL injection — HTTP input concatenated into a MySQL query
    cur.execute("SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'")
    rows = cur.fetchall()
    con.close()
    return jsonify(rows)
