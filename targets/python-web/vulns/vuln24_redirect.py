from flask import Blueprint, request, redirect
bp = Blueprint("vuln24", __name__)

@bp.get("/vuln24/redirect")
def r():
    url = request.args.get("url", "")
    # VULN:VULN-24:CWE-601:taint open redirect — unvalidated redirect target
    return redirect(url)
