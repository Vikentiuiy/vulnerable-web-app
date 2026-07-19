from flask import Blueprint, request, Response
bp = Blueprint("vuln03", __name__)

@bp.get("/vuln03/echo")
def echo():
    q = request.args.get("q", "")
    # VULN:VULN-03:CWE-79:taint reflected XSS: input echoed into HTML unescaped
    return Response("<html><body><h3>You searched for: " + q + "</h3></body></html>", mimetype="text/html")
