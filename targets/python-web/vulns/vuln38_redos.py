import re, time
from flask import Blueprint, request, jsonify
bp = Blueprint("vuln38", __name__)
# VULN:VULN-38:CWE-1333:logic catastrophically-backtracking regex applied to user input
_EVIL = re.compile(r"^(.*a){12}$")

@bp.get("/vuln38/validate")
def validate():
    email = request.args.get("email", "")[:30]
    t0 = time.time()
    ok = bool(_EVIL.match(email))
    return jsonify({"valid": ok, "ms": int((time.time() - t0) * 1000)})
