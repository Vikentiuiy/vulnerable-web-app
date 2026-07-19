import hashlib
from flask import Blueprint, request
bp = Blueprint("vuln13", __name__)

@bp.get("/vuln13/hash")
def hash_():
    p = request.args.get("p", "")
    # VULN:VULN-13:CWE-327:pattern broken/weak hash (MD5) used for passwords
    return hashlib.md5(p.encode()).hexdigest()
