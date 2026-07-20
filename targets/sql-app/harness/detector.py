# HARNESS (out of scan scope). Flask after_request instrumentation.
import re
from flask import request
from harness.tracker import TRACKER


def _p(n):
    return request.args.get(n) or (request.form.get(n) if request.form else None)


def install(app):
    @app.after_request
    def _detect(response):
        path = request.path
        if path.startswith("/vuln"):
            try:
                if path.startswith("/vuln81") and re.search(r"(?i)(union|select|--|')", _p("q") or ""):
                    TRACKER.mark("VULN-81", "app SQLi payload processed")
                if path.startswith("/vuln82") and any(x in (_p("username") or "") for x in ("'", "--")):
                    TRACKER.mark("VULN-82", "app auth-bypass payload")
                if path.startswith("/vuln83") and re.search(r"(?i)(union|select|--|')", _p("q") or ""):
                    TRACKER.mark("VULN-83", "proc-mediated SQLi payload")
                if path.startswith("/vuln84") and re.search(r"(?i)(union|select|--|')", _p("name") or ""):
                    TRACKER.mark("VULN-84", "f-string SQLi payload")
                if path.startswith("/vuln85") and re.search(r"(?i)(union|select|--|'| or )", _p("role") or ""):
                    TRACKER.mark("VULN-85", "str.format SQLi payload")
                if path.startswith("/vuln87") and re.search(r"[;|&`$]", _p("host") or ""):
                    TRACKER.mark("VULN-87", "command injection (control)")
                if path.startswith("/vuln86") and re.search(r"(?i)(select|union|--|\(|;| )", _p("col") or ""):
                    TRACKER.mark("VULN-86", "ORDER BY SQLi payload")
                if path.startswith("/vuln88") and re.search(r"(?i)(select|union|--|or |'| )", _p("id") or ""):
                    TRACKER.mark("VULN-88", "numeric-context SQLi payload")
                if path.startswith("/vuln92") and re.search(r"(?i)(union|select|--|')", _p("name") or ""):
                    TRACKER.mark("VULN-92", "LIKE SQLi payload")
                if path.startswith("/vuln93") and re.search(r"(?i)(union|select|--|')", (_p("name") or "") + (_p("id") or "")):
                    TRACKER.mark("VULN-93", "UPDATE SQLi payload")
                if path.startswith("/vuln94") and re.search(r"(?i)(union|select|--|')", _p("ids") or ""):
                    TRACKER.mark("VULN-94", "IN-list SQLi payload")
                if path.startswith("/vuln89"):
                    t = _p("term") or ""
                    if re.search(r"(?i)(union|select|--|')", t):
                        TRACKER.mark("VULN-89", "combo SQLi payload")
                    if re.search(r"[;|&`$]", t):
                        TRACKER.mark("VULN-90", "combo command injection (control)")
            except Exception:
                pass
        return response
