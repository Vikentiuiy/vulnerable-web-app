from flask import Blueprint, request
from lxml import etree
bp = Blueprint("vuln09", __name__)

@bp.post("/vuln09/xml")
def xml():
    body = request.get_data()
    # VULN:VULN-09:CWE-611:taint XXE — external entity resolution enabled (lxml)
    parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
    doc = etree.fromstring(body, parser)
    return "parsed: " + (doc.text or "")
