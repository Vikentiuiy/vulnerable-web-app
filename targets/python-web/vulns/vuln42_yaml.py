import yaml
from flask import Blueprint, request
bp = Blueprint("vuln42", __name__)

@bp.post("/vuln42/yaml")
def load_yaml():
    body = request.get_data()
    # VULN:VULN-42:CWE-502:taint unsafe YAML load (executes !!python tags)
    obj = yaml.load(body, Loader=yaml.Loader)
    return "loaded: " + str(type(obj).__name__)
