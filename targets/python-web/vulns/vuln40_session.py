from flask import Blueprint, request, make_response, jsonify
bp = Blueprint("vuln40", __name__)

@bp.get("/vuln40/setsession")
def setsession():
    sid = request.args.get("sid", "")
    resp = make_response(jsonify({"session": sid}))
    # VULN:VULN-40:CWE-384:logic session id taken from the request and set as-is
    resp.set_cookie("session", sid)
    return resp
