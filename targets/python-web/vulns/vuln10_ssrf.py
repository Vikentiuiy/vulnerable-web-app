import requests
from flask import Blueprint, request
bp = Blueprint("vuln10", __name__)

@bp.get("/vuln10/fetch")
def fetch():
    url = request.args.get("url", "")
    # VULN:VULN-10:CWE-918:taint SSRF — server fetches an arbitrary user-supplied URL
    return requests.get(url, timeout=4).text
