from flask import Blueprint, request, Response, jsonify
bp = Blueprint("vuln04", __name__)
_store = {}

@bp.post("/vuln04/save")
def save():
    _store[request.form.get("id", "")] = request.form.get("bio", "")
    return jsonify({"status": "saved"})

@bp.get("/vuln04/show")
def show():
    bio = _store.get(request.args.get("id", ""), "")
    # VULN:VULN-04:CWE-79:taint stored XSS: persisted bio rendered unescaped
    return Response("<html><body><div>" + bio + "</div></body></html>", mimetype="text/html")
