from flask import Blueprint, request
bp = Blueprint("vuln06", __name__)

@bp.get("/vuln06/download")
def download():
    name = request.args.get("name", "")
    # VULN:VULN-06:CWE-22:taint path traversal — user input concatenated into a filesystem path
    with open("/app/data/" + name, "rb") as f:
        return f.read()
