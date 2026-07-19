import subprocess

from flask import Blueprint, request, jsonify
from store import get_db

bp = Blueprint("vuln89", __name__)


# THE IRONCLAD PROOF: a single tainted HTTP parameter flows into TWO sinks on
# adjacent lines — an OS command (PT AI detects) and a SQL query (PT AI misses).
# If the scan flags the command injection but not the SQL injection right below
# it, the SQLi miss cannot be blamed on the pipeline, the entry point, or taint
# reachability — it is a SQL-injection sink blind spot.
@bp.get("/vuln89/combo")
def combo():
    term = request.args.get("term", "")
    # VULN:VULN-90:CWE-78:taint OS command injection on `term` (positive control — detected)
    label = subprocess.getoutput("echo " + term)
    con = get_db()
    cur = con.cursor()
    # VULN:VULN-89:CWE-89:taint SQL injection on the SAME `term` (expected miss — blind spot)
    cur.execute("SELECT id, name FROM products WHERE name = '" + term + "'")
    rows = cur.fetchall()
    con.close()
    return jsonify({"label": label.strip(), "rows": rows})
