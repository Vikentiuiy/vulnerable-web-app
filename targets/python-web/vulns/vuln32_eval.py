from flask import Blueprint, request
bp = Blueprint("vuln32", __name__)

@bp.get("/vuln32/calc")
def calc():
    expr = request.args.get("expr", "")
    # VULN:VULN-32:CWE-95:taint code injection — user input passed to eval()
    return "result: " + str(eval(expr))
