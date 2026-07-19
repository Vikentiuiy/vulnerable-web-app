import subprocess

from flask import Blueprint, request

bp = Blueprint("vuln87", __name__)


# POSITIVE CONTROL: an OS command injection from the SAME kind of HTTP taint
# source as the SQL sinks. PT AI's Python engine DOES detect this — proving the
# scan pipeline, entry-point recognition and taint tracking all work here, so a
# 0 on the neighbouring SQL injections is a genuine SQLi sink blind spot.
@bp.get("/vuln87/ping")
def ping():
    host = request.args.get("host", "")
    # VULN:VULN-87:CWE-78:taint OS command injection (positive control — expected to be detected)
    return subprocess.getoutput("ping -c 1 " + host)
