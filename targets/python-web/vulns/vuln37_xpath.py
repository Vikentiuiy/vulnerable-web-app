from flask import Blueprint, request
from lxml import etree
bp = Blueprint("vuln37", __name__)
_DOC = etree.fromstring(b"<users><user><name>admin</name><role>admin</role></user><user><name>alice</name><role>user</role></user></users>")

@bp.get("/vuln37/xlookup")
def xlookup():
    user = request.args.get("user", "")
    # VULN:VULN-37:CWE-643:taint user input concatenated into an XPath expression
    nodes = _DOC.xpath("/users/user[name='" + user + "']/role/text()")
    return "roles: " + ",".join(nodes)
