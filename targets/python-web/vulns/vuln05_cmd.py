import subprocess
from flask import Blueprint, request
bp = Blueprint("vuln05", __name__)

@bp.get("/vuln05/ping")
def ping():
    host = request.args.get("host", "")
    # VULN:VULN-05:CWE-78:taint OS command injection — host concatenated into a shell command
    return subprocess.getoutput("ping -c 1 " + host)
