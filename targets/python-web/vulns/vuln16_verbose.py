import traceback
from flask import Blueprint, request
from store import get_db
bp = Blueprint("vuln16", __name__)

@bp.get("/vuln16/lookup")
def lookup():
    uid = request.args.get("id", "")
    try:
        con = get_db()
        con.execute("SELECT * FROM users WHERE id = " + uid).fetchone()
        return {"status": "ok"}
    except Exception:
        # VULN:VULN-16:CWE-209:logic full traceback returned to the client
        return "error:\n" + traceback.format_exc(), 500
