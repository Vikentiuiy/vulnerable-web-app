from flask import Blueprint, request, Response

bp = Blueprint("vuln93", __name__)


@bp.get("/vuln93/attr")
def attr():
    color = request.args.get("color", "blue")
    # VULN:VULN-93:CWE-79:taint reflected XSS in an HTML attribute context (unquoted breakout)
    return Response("<html><body><div style='color:" + color + "'>hello</div></body></html>", mimetype="text/html")
