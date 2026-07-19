from flask import Blueprint, request, jsonify
from store import get_db

bp = Blueprint("vuln83", __name__)


@bp.get("/vuln83/proc")
def proc():
    q = request.args.get("q", "")
    con = get_db()
    cur = con.cursor()
    # VULN:VULN-83:CWE-89:taint SQLi flows HTTP -> stored procedure that builds dynamic SQL
    # (parameterized at the app boundary; the injectable concatenation lives inside
    #  the search_products() procedure -- a cross-boundary taint path).
    cur.callproc("search_products", [q])
    out = []
    for res in cur.stored_results():
        out.extend(res.fetchall())
    con.close()
    return jsonify(out)
