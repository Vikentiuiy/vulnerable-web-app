#!/usr/bin/env python3
"""
build_reference.py — Generate the ground-truth reference.sarif for the
vulnerable-web-app fixture by scanning the source tree for planted markers.

Every planted, exploitable weakness is tagged in the source with a comment of
the form:

    VULN:VULN-01:CWE-89 <free text description>

This script walks the repo, finds every such marker, and emits a SARIF 2.1.0
document with one result per marker (file + line + ruleId + CWE + vulnId).
Keeping the reference generated-from-source guarantees the line numbers in
reference.sarif always match the actual code.

Usage:
    python3 checker/build_reference.py                 # writes checker/reference.sarif
    python3 checker/build_reference.py -o out.sarif
"""

import argparse
import json
import os
import re
import sys

# VULN:VULN-01:CWE-89:taint <desc>   (the :class segment is optional, one of
# taint|pattern|config|sca|logic — see docs/benchmark-methodology.md)
MARKER_RE = re.compile(r'VULN:(VULN-\d+):(CWE-\d+)(?::([a-z]+))?\s*(.*)')

# File extensions that may contain markers (all benchmark languages).
SCAN_EXTS = {".java", ".kt", ".js", ".ts", ".py", ".sql", ".html", ".properties",
             ".xml", ".yml", ".yaml", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
             ".m", ".mm", ".swift", ".go", ".rb", ".php", ".kts"}

# Directories to skip.
SKIP_DIRS = {".git", "target", "node_modules", "checker"}

# Human-readable name per CWE (used as the SARIF rule name so that name->CWE
# mapping in sast_checker.py also resolves).
CWE_NAMES = {
    "CWE-89":  "SQL Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-site Scripting",
    "CWE-22":  "Path Traversal",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-611": "XML External Entity",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-200": "Information Exposure",
    "CWE-639": "Authorization Bypass (IDOR)",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-209": "Information Exposure Through Error Message",
    "CWE-614": "Sensitive Cookie Without Secure/HttpOnly",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-256": "Plaintext Storage of a Password",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-329": "Not Using a Random IV with CBC Mode",
    "CWE-321": "Use of Hard-coded Cryptographic Key",
    "CWE-601": "Open Redirect",
    "CWE-470": "Unsafe Reflection",
    "CWE-95":  "Code Injection (eval)",
    "CWE-915": "Mass Assignment",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-347": "Improper Verification of Cryptographic Signature (JWT)",
    "CWE-917": "Expression Language Injection",
    "CWE-1236": "Improper Neutralization of Formula Elements in a CSV File",
    "CWE-942": "Overly Permissive Cross-domain Whitelist (CORS)",
    "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-643": "XPath Injection",
    "CWE-1333": "Inefficient Regular Expression Complexity (ReDoS)",
    "CWE-117": "Improper Output Neutralization for Logs",
    "CWE-384": "Session Fixation",
}


def find_markers(root):
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1]
            if ext not in SCAN_EXTS:
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root).replace("\\", "/")
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for lineno, line in enumerate(f, start=1):
                        m = MARKER_RE.search(line)
                        if not m:
                            continue
                        vuln_id, cwe = m.group(1), m.group(2)
                        dclass = (m.group(3) or "unknown").strip()
                        desc = m.group(4).strip()
                        findings.append({
                            "vulnId": vuln_id,
                            "cwe": cwe,
                            "dclass": dclass,
                            "uri": rel,
                            "line": lineno,
                            "desc": desc or CWE_NAMES.get(cwe, cwe),
                        })
            except OSError:
                continue
    return findings


def build_sarif(findings):
    # One rule per distinct CWE.
    cwes = sorted({f["cwe"] for f in findings}, key=lambda c: int(c.split("-")[1]))
    rules = []
    rule_index = {}
    for i, cwe in enumerate(cwes):
        rule_index[cwe] = i
        rules.append({
            "id": cwe,
            "name": CWE_NAMES.get(cwe, cwe),
            "shortDescription": {"text": CWE_NAMES.get(cwe, cwe)},
            "properties": {"cwe": cwe, "tags": [cwe]},
        })

    results = []
    for f in findings:
        results.append({
            "ruleId": f["cwe"],
            "ruleIndex": rule_index[f["cwe"]],
            "level": "error",
            "message": {"text": f"[{f['vulnId']}] {f['cwe']} ({f['dclass']}): {f['desc']}"},
            "properties": {"vulnId": f["vulnId"], "cwe": f["cwe"], "dclass": f["dclass"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["uri"]},
                    "region": {"startLine": f["line"]},
                }
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "vulnerable-web-app-reference",
                "informationUri": "https://github.com/Vikentiuiy/vulnerable-web-app",
                "version": "1.0.0",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(here)
    ap.add_argument("--root", default=repo_root, help="repo root to scan")
    ap.add_argument("-o", "--output", default=os.path.join(here, "reference.sarif"))
    args = ap.parse_args()

    findings = find_markers(args.root)
    findings.sort(key=lambda f: (f["uri"], f["line"]))
    sarif = build_sarif(findings)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)
        f.write("\n")

    by_cwe = {}
    for x in findings:
        by_cwe[x["cwe"]] = by_cwe.get(x["cwe"], 0) + 1
    by_class = {}
    for x in findings:
        by_class[x.get("dclass", "unknown")] = by_class.get(x.get("dclass", "unknown"), 0) + 1
    print(f"Wrote {len(findings)} reference findings to {args.output}")
    print(f"Distinct vuln ids: {len(set(x['vulnId'] for x in findings))}")
    print(f"Distinct CWEs: {len(by_cwe)}")
    print("By detection class: " + ", ".join(f"{k}={v}" for k, v in sorted(by_class.items())))
    for cwe in sorted(by_cwe, key=lambda c: int(c.split('-')[1])):
        print(f"  {cwe:8} x{by_cwe[cwe]}  {CWE_NAMES.get(cwe,'')}")


if __name__ == "__main__":
    main()
