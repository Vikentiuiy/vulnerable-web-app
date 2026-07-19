# HARNESS (out of scan scope). The ONLY instrumentation point: a Flask
# after_request hook that observes each request/response and marks the tracker
# when a genuinely-malicious payload hits a planted endpoint. Keeps the vuln
# blueprints clean of detection logic.
import re
from flask import request
from harness.tracker import TRACKER

_v30 = {"n": 0}


def _p(name):
    return request.args.get(name) or request.form.get(name)


def install(app):
    @app.after_request
    def _detect(response):
        path = request.path
        if not path.startswith("/vuln"):
            return response
        try:
            body = request.get_data(as_text=True) or ""
            try:
                data = response.get_data(as_text=True)
            except Exception:
                data = ""
            m = TRACKER.mark
            if path.startswith("/vuln01") and re.search(r"(?is)(union|select|--|'|information_schema)", _p("q") or ""):
                m("VULN-01", "SQLi payload processed")
            if path.startswith("/vuln02") and any(x in (_p("username") or "") for x in ("'", "--")):
                m("VULN-02", "auth bypass payload")
            if path.startswith("/vuln03") and re.search(r"(?i)(<script|onerror=|<img|<svg)", _p("q") or ""):
                m("VULN-03", "reflected XSS echoed")
            if path.startswith("/vuln04/save") and re.search(r"(?i)(<script|onerror=|<img|<svg)", _p("bio") or ""):
                m("VULN-04", "stored XSS persisted")
            if path.startswith("/vuln05") and re.search(r"[;|&`$\n]", _p("host") or ""):
                m("VULN-05", "command injection")
            if path.startswith("/vuln06") and (".." in (_p("name") or "") or (_p("name") or "").startswith("/")):
                m("VULN-06", "path traversal")
            if path.startswith("/vuln08"):
                m("VULN-08", "pickle.loads on untrusted bytes")
            if path.startswith("/vuln09") and ("<!ENTITY" in body or "<!DOCTYPE" in body):
                m("VULN-09", "XXE external entity processed")
            if path.startswith("/vuln10") and _p("url"):
                m("VULN-10", "SSRF fetched URL")
            if path.startswith("/vuln11") and re.search(r"\d{3}-\d{2}-\d{4}", data):
                m("VULN-11", "SSN exposed")
            if path.startswith("/vuln12"):
                m("VULN-12", "object accessed w/o authz")
            if path.startswith("/vuln13"):
                m("VULN-13", "unsalted MD5 hashing")
            if path.startswith("/vuln16") and re.search(r"(?i)(traceback|error|sqlite)", data):
                m("VULN-16", "verbose error/traceback leaked")
            if path.startswith("/vuln17"):
                sc = response.headers.get("Set-Cookie", "")
                if "auth=" in sc and "httponly" not in sc.lower():
                    m("VULN-17", "cookie without HttpOnly")
            if path.startswith("/vuln18") and _p("user"):
                m("VULN-18", "predictable token issued")
            if path.startswith("/vuln24") and re.match(r"(?i)^(https?:)?//", _p("url") or ""):
                m("VULN-24", "open redirect")
            if path.startswith("/vuln29") and _p("role") and (_p("role") or "").lower() != "user":
                m("VULN-29", "role escalated")
            if path.startswith("/vuln32") and _p("expr"):
                m("VULN-32", "eval of user expression")
            if path.startswith("/vuln33") and re.match(r"^[=+\-@]", _p("note") or ""):
                m("VULN-33", "CSV formula injected")
            if path.startswith("/vuln34") and request.headers.get("Origin"):
                m("VULN-34", "CORS reflected origin")
            if path.startswith("/vuln37") and re.search(r"('|\bor\b)", _p("user") or ""):
                m("VULN-37", "XPath injection")
            if path.startswith("/vuln38") and len(_p("email") or "") > 20:
                m("VULN-38", "ReDoS input")
            if path.startswith("/vuln39") and re.search(r"[\r\n]", _p("text") or ""):
                m("VULN-39", "CRLF log injection")
            if path.startswith("/vuln40") and _p("sid"):
                m("VULN-40", "session fixation")
            if path.startswith("/vuln41") and _p("name") and ("{{" in (_p("name") or "") or "{%" in (_p("name") or "")):
                m("VULN-41", "SSTI template expression evaluated")
            if path.startswith("/vuln42") and ("!!python" in body or "!!" in body):
                m("VULN-42", "unsafe YAML tag processed")
            if path.startswith("/vuln91"):
                q = _p("q") or ""
                if re.search(r"(?i)(<script|onerror=|<img|<svg)", q):
                    m("VULN-91", "reflected XSS payload echoed")
                if re.search(r"[;|&`$]", q):
                    m("VULN-92", "command injection (control)")
            if path.startswith("/vuln93") and re.search(r"(?i)(onmouseover|onerror|<script|javascript:|')", _p("color") or ""):
                m("VULN-93", "attribute-context XSS payload")
            if path.startswith("/vuln94") and re.search(r"(?i)(</script|';|alert|<script)", _p("name") or ""):
                m("VULN-94", "JS-context XSS payload")
        except Exception:
            pass
        # VULN-35 clickjacking: app never sets X-Frame-Options (marked at config level)
        return response
