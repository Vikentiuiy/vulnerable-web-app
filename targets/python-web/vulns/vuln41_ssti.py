from flask import Blueprint, request, render_template_string
bp = Blueprint("vuln41", __name__)

@bp.get("/vuln41/greet")
def greet():
    name = request.args.get("name", "guest")
    # VULN:VULN-41:CWE-1336:taint SSTI — user input rendered as a Jinja2 template
    return render_template_string("<h3>Hello " + name + "</h3>")
