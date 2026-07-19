from flask import Blueprint, request, jsonify
from store import get_db

bp = Blueprint("vuln85", __name__)


@bp.get("/vuln85/byrole")
def byrole():
    role = request.args.get("role", "")
    con = get_db()
    cur = con.cursor()
    # VULN:VULN-85:CWE-89:taint SQL injection — str.format() interpolation of HTTP input
    cur.execute("SELECT id, username FROM users WHERE role = '{}'".format(role))
    rows = cur.fetchall()
    con.close()
    return jsonify(rows)
