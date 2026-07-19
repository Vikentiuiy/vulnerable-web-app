import subprocess

from flask import Blueprint, request, Response

bp = Blueprint("vuln91", __name__)


# IRONCLAD XSS PROOF: one tainted parameter flows into TWO sinks on adjacent
# lines — an OS command (PT AI's Python engine detects) and reflected HTML (XSS,
# which it misses). If the command injection is flagged but the XSS is not, the
# XSS miss is a genuine sink blind spot, not a pipeline/entry-point issue.
@bp.get("/vuln91/combo")
def combo():
    q = request.args.get("q", "")
    # VULN:VULN-92:CWE-78:taint OS command injection on `q` (positive control — detected)
    label = subprocess.getoutput("echo " + q)
    # VULN:VULN-91:CWE-79:taint reflected XSS on the SAME `q` (expected miss — blind spot)
    return Response("<html><body><p>" + label + "</p><h3>" + q + "</h3></body></html>", mimetype="text/html")
