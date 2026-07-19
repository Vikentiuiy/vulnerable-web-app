import random
from flask import Blueprint, request, make_response
bp = Blueprint("vuln17", __name__)

@bp.get("/vuln17/login")
def login():
    user = request.args.get("user", "guest")
    token = "%016x" % random.Random(hash(user)).getrandbits(64)
    resp = make_response({"status": "ok", "token": token})
    # VULN:VULN-17:CWE-614:config auth cookie set without HttpOnly/Secure flags
    resp.set_cookie("auth", token, httponly=False, secure=False)
    return resp
