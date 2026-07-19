import logging
from flask import Blueprint, request, jsonify
bp = Blueprint("vuln39", __name__)
_log = logging.getLogger("audit")

@bp.get("/vuln39/note")
def note():
    text = request.args.get("text", "")
    # VULN:VULN-39:CWE-117:taint user input logged without neutralising CR/LF
    _log.warning("user note: " + text)
    return jsonify({"logged": True})
