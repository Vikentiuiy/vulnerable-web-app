import random
from flask import Blueprint, request
bp = Blueprint("vuln18", __name__)

@bp.get("/vuln18/token")
def token():
    user = request.args.get("user", "")
    # VULN:VULN-18:CWE-330:pattern predictable token from a seedable, non-CSPRNG generator
    rng = random.Random(hash(user))
    return "".join("%x" % rng.randint(0, 15) for _ in range(16))
