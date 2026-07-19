import base64, pickle
from flask import Blueprint, request
bp = Blueprint("vuln08", __name__)

@bp.post("/vuln08/deserialize")
def deserialize():
    raw = base64.b64decode(request.get_data())
    # VULN:VULN-08:CWE-502:taint deserialization of untrusted data (pickle RCE)
    obj = pickle.loads(raw)
    return "deserialized: " + type(obj).__name__
