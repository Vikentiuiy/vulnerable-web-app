from flask import Blueprint, request, Response

bp = Blueprint("vuln94", __name__)


@bp.get("/vuln94/jsctx")
def jsctx():
    name = request.args.get("name", "guest")
    # VULN:VULN-94:CWE-79:taint reflected XSS in a JavaScript string context
    return Response("<html><body><script>var u = '" + name + "'; document.write(u);</script></body></html>",
                    mimetype="text/html")
