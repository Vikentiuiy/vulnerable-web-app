from flask import Blueprint, request, jsonify
from store import get_db
bp = Blueprint("vuln93", __name__)

@bp.post("/vuln93/rename")
def rename():
    pid = request.form.get("id", "0"); name = request.form.get("name", "")
    con = get_db(); cur = con.cursor()
    # VULN:VULN-93:CWE-89:taint SQL injection in an UPDATE statement (both values concatenated)
    cur.execute("UPDATE products SET name = '" + name + "' WHERE id = " + pid)
    con.commit(); con.close()
    return jsonify({"status": "renamed"})
