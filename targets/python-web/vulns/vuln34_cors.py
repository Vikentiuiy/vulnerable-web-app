from flask import Blueprint, request, make_response
bp = Blueprint("vuln34", __name__)

@bp.get("/vuln34/data")
def data():
    resp = make_response({"secret": "account-balance-42000"})
    origin = request.headers.get("Origin")
    if origin:
        # VULN:VULN-34:CWE-942:config arbitrary Origin reflected + credentials allowed
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp
