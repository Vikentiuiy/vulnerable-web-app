from flask import Blueprint, request, Response
bp = Blueprint("vuln33", __name__)

@bp.get("/vuln33/export")
def export():
    note = request.args.get("note", "")
    # VULN:VULN-33:CWE-1236:taint user data written into CSV without neutralising formulas
    return Response("id,note\n1," + note + "\n", mimetype="text/csv")
