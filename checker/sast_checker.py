#!/usr/bin/env python3
"""
sast_checker.py — Compare a SAST tool's SARIF output against a reference
(ground-truth) SARIF for the vulnerable-java-app test fixture.

It reports how many of the planted (reference) vulnerabilities were detected,
plus precision / recall / F1 and lists of matched / missed / extra findings.

Matching strategy (configurable):
  - "location" (default): a tool finding matches a reference finding if it points
    to the same file and a line within +/- tolerance of the reference sink line.
    Optionally also require the CWE to match (--require-cwe).
  - "cwe": match purely by CWE presence (coarse; ignores location). Useful when a
    tool reports the right class of bug but at a slightly different line/file.

Each reference finding can be matched by at most one tool finding and vice versa
(greedy one-to-one matching), so duplicate tool findings don't inflate recall.

Usage:
  python3 sast_checker.py --reference reference.sarif --actual tool_output.sarif
  python3 sast_checker.py -r reference.sarif -a out.sarif --tolerance 3 --require-cwe
  python3 sast_checker.py -r reference.sarif -a out.sarif --match cwe --json report.json

Exit code is 0 unless --fail-under is set and recall is below the threshold.
"""

import argparse
import json
import os
import re
import sys


CWE_RE = re.compile(r'CWE[-_ ]?(\d+)', re.IGNORECASE)

# ---------------------------------------------------------------------------
# Rule-name -> CWE mapping.
#
# Many SAST tools (e.g. PT Application Inspector, some SpotBugs/Semgrep configs)
# do NOT embed CWE ids in their SARIF. Instead the ruleId is a human-readable
# vulnerability name. This table maps those names to the CWE(s) used in the
# reference SARIF so that CWE-based matching works.
#
# Keys are matched case-insensitively against the ruleId AND the rule name.
# A single tool rule may map to several CWEs (any overlap counts as a match).
# ---------------------------------------------------------------------------
RULE_NAME_TO_CWE = {
    "sql injection": ["CWE-89"],
    "os commanding": ["CWE-78"],
    "os command injection": ["CWE-78"],
    "command injection": ["CWE-78"],
    "remote code execution": ["CWE-78", "CWE-502", "CWE-470"],
    "ldap injection": ["CWE-90"],
    "xpath injection": ["CWE-643"],
    "cross-site scripting": ["CWE-79"],
    "xss": ["CWE-79"],
    "open redirect": ["CWE-601"],
    "http response splitting": ["CWE-113"],
    "crlf injection": ["CWE-113"],
    "cookie injection": ["CWE-113", "CWE-614"],
    "sensitive cookie in https session without secure attribute": ["CWE-614"],
    "sensitive cookie without secure/httponly": ["CWE-614"],
    "session fixation": ["CWE-384"],
    "path traversal": ["CWE-22"],
    "potential path traversal": ["CWE-22"],
    "arbitrary file reading": ["CWE-22"],
    "arbitrary file modification": ["CWE-22"],
    "arbitrary file creation": ["CWE-22", "CWE-377"],
    "zip slip": ["CWE-22"],
    "server-side request forgery": ["CWE-918"],
    "ssrf": ["CWE-918"],
    "insecure temporary file": ["CWE-377"],
    "use of function with inconsistent implementations": ["CWE-377"],
    "incorrect permission assignment": ["CWE-732"],
    "use of hard-coded credentials": ["CWE-798"],
    "use of hard-coded password": ["CWE-259", "CWE-798"],
    "hardcoded credentials": ["CWE-798"],
    "missing encryption of sensitive data": ["CWE-311", "CWE-327"],
    "use of a broken or risky cryptographic algorithm": ["CWE-327"],
    "broken/risky crypto algorithm": ["CWE-327"],
    "weak cryptographic hash": ["CWE-327", "CWE-328"],
    "not using random iv with cbc": ["CWE-329"],
    "static initialization vector": ["CWE-329"],
    "use of insufficiently random values": ["CWE-330"],
    "static random number generator": ["CWE-330"],
    "insufficiently random values": ["CWE-330"],
    "incorrect usage of seeds in pseudo-random number generator": ["CWE-337", "CWE-330"],
    "predictable seed in prng": ["CWE-337"],
    "deserialization of untrusted data": ["CWE-502"],
    "xml external entity": ["CWE-611"],
    "xxe": ["CWE-611"],
    "unsafe reflection": ["CWE-470"],
    "log injection": ["CWE-117"],
    "log forging": ["CWE-117"],
    "information exposure through error message": ["CWE-209"],
    "exposure of system data to an unauthorized control sphere": ["CWE-209", "CWE-497"],
    "improper certificate validation": ["CWE-295"],
    "observable timing discrepancy": ["CWE-208"],
    "null pointer dereference": ["CWE-476"],
    "trust boundary violation": ["CWE-501"],
    # --- extended set (VULN-44..100) ---
    "missing authentication for critical function": ["CWE-306"],
    "missing authentication": ["CWE-306"],
    "authorization bypass": ["CWE-639", "CWE-862"],
    "idor": ["CWE-639"],
    "insecure direct object reference": ["CWE-639"],
    "broken access control": ["CWE-639", "CWE-284"],
    "improper privilege management": ["CWE-269"],
    "privilege escalation": ["CWE-269"],
    "plaintext storage of password": ["CWE-256"],
    "cleartext storage of password": ["CWE-256"],
    "inadequate encryption strength": ["CWE-326"],
    "improper authentication": ["CWE-287"],
    "permissive cors": ["CWE-942"],
    "overly permissive cross-origin resource sharing": ["CWE-942"],
    "cross-origin resource sharing": ["CWE-942"],
    "clickjacking": ["CWE-1021"],
    "improper restriction of rendered ui layers": ["CWE-1021"],
    "weak password requirements": ["CWE-521"],
    "nosql injection": ["CWE-943"],
    "expression language injection": ["CWE-917"],
    "el injection": ["CWE-917"],
    "code injection": ["CWE-94"],
    "server-side template injection": ["CWE-1336", "CWE-94"],
    "template injection": ["CWE-1336"],
    "ssti": ["CWE-1336"],
    "crlf injection": ["CWE-93"],
    "email header injection": ["CWE-93"],
    "uncontrolled format string": ["CWE-134"],
    "format string": ["CWE-134"],
    "improper verification of cryptographic signature": ["CWE-347"],
    "jwt signature not verified": ["CWE-347"],
    "improper restriction of excessive authentication attempts": ["CWE-307"],
    "missing rate limiting": ["CWE-307"],
    "mass assignment": ["CWE-915"],
    "information exposure through query string": ["CWE-598"],
    "sensitive information in url": ["CWE-598"],
    "insufficient verification of data authenticity": ["CWE-345"],
    "race condition": ["CWE-362"],
    "toctou": ["CWE-367"],
    "time-of-check time-of-use": ["CWE-367"],
    "missing release of resource": ["CWE-772"],
    "resource leak": ["CWE-772"],
    "unclosed resource": ["CWE-772"],
    "inefficient regular expression": ["CWE-1333"],
    "redos": ["CWE-1333"],
    "regular expression denial of service": ["CWE-1333"],
    "uncontrolled memory allocation": ["CWE-789"],
    "integer overflow": ["CWE-190"],
    "loop with unreachable exit condition": ["CWE-835"],
    "infinite loop": ["CWE-835"],
    "configuration": ["CWE-16"],
    "insecure default configuration": ["CWE-16"],
    "active debug code": ["CWE-489"],
    "debug code": ["CWE-489"],
    "information exposure through directory listing": ["CWE-548"],
    "directory listing": ["CWE-548"],
    "information exposure": ["CWE-200"],
    "information disclosure": ["CWE-200"],
    "unrestricted file upload": ["CWE-434"],
    "unrestricted upload of file with dangerous type": ["CWE-434"],
    "insertion of sensitive information into log file": ["CWE-532"],
    "sensitive data in logs": ["CWE-532"],
    "improper input validation": ["CWE-20"],
    "improper encoding or escaping of output": ["CWE-116"],
    "improper output encoding": ["CWE-116"],
    "password hash without salt": ["CWE-759"],
    "use of password hash with insufficient computational effort": ["CWE-916"],
    "weak password hash": ["CWE-916"],
    "incorrect numeric conversion": ["CWE-681"],
    "client-side enforcement of server-side security": ["CWE-602"],
    "use of wrong operator in string comparison": ["CWE-597"],
    "reference comparison": ["CWE-597"],
    "cleartext storage of sensitive information": ["CWE-312"],
    "improper neutralization of null byte": ["CWE-158"],
    "null byte injection": ["CWE-158"],
    "divide by zero": ["CWE-369"],
    "division by zero": ["CWE-369"],
    "omitted break in switch": ["CWE-484"],
    "switch fall-through": ["CWE-484"],
    "reachable assertion": ["CWE-617"],
    "security check via assert": ["CWE-617"],
}


def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


def load_sarif(path):
    if not os.path.isfile(path):
        eprint(f"ERROR: file not found: {path}")
        sys.exit(2)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        eprint(f"ERROR: {path} is not valid JSON: {e}")
        sys.exit(2)


def norm_path(uri):
    """Normalize a SARIF artifact URI to a comparable relative path."""
    if uri is None:
        return ""
    u = str(uri)
    if u.startswith("file://"):
        u = u[len("file://"):]
    # strip scheme-ish leading slashes duplicates, backslashes -> slashes
    u = u.replace("\\", "/")
    # drop any leading ./ and leading slashes for comparison
    u = re.sub(r'^/+', '', u)
    u = re.sub(r'^\./', '', u)
    return u


def path_key(uri):
    """A loose key for path comparison: basename + up to 2 parent dirs."""
    u = norm_path(uri)
    parts = [p for p in u.split("/") if p]
    return "/".join(parts[-3:]) if parts else u


def cwes_from_name(*names):
    """Map tool rule names/ids to CWEs via RULE_NAME_TO_CWE (case-insensitive)."""
    found = set()
    for name in names:
        if not name:
            continue
        key = str(name).strip().lower()
        if key in RULE_NAME_TO_CWE:
            found.update(RULE_NAME_TO_CWE[key])
    return found


def extract_cwes(result, rules_by_id):
    """Collect CWE ids (as strings like 'CWE-89') from a SARIF result.

    Sources, in order:
      1. Literal 'CWE-nnn' text anywhere in the result/rule metadata.
      2. Tool rule NAME/id mapped through RULE_NAME_TO_CWE (for tools that don't
         emit CWE ids at all, e.g. PT Application Inspector).
    """
    cwes = set()

    def scan(obj):
        for m in CWE_RE.finditer(json.dumps(obj, ensure_ascii=False)):
            cwes.add(f"CWE-{m.group(1)}")

    # result-level properties + message + ruleId
    scan(result.get("properties", {}))
    msg = result.get("message", {})
    if isinstance(msg, dict):
        scan(msg.get("text", ""))
    rid = result.get("ruleId", "")
    scan(rid)

    rule = rules_by_id.get(rid)
    rule_name = None
    if rule:
        scan(rule.get("properties", {}))
        scan(rule.get("shortDescription", {}))
        scan(rule.get("fullDescription", {}))
        for tax in rule.get("relationships", []):
            scan(tax)
        rule_name = rule.get("name")

    # Fallback: map by human-readable rule name / id.
    cwes |= cwes_from_name(rid, rule_name)
    return cwes


def parse_results(sarif):
    """Yield normalized finding dicts from every run in a SARIF doc."""
    findings = []
    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = driver.get("rules", []) or []
        rules_by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
        # also index extension rules
        for ext in run.get("tool", {}).get("extensions", []) or []:
            for r in ext.get("rules", []) or []:
                if isinstance(r, dict):
                    rules_by_id.setdefault(r.get("id"), r)

        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            # ruleId may instead be given as ruleIndex
            if not rid and isinstance(res.get("ruleIndex"), int):
                idx = res["ruleIndex"]
                if 0 <= idx < len(rules):
                    rid = rules[idx].get("id", "")
            cwes = extract_cwes(res, rules_by_id)
            locs = res.get("locations", []) or []
            # take first physical location (typical for a primary sink)
            uri, line = None, None
            for loc in locs:
                pl = loc.get("physicalLocation", {})
                art = pl.get("artifactLocation", {})
                uri = art.get("uri")
                region = pl.get("region", {})
                line = region.get("startLine")
                if uri is not None:
                    break
            # message text may be inline, or referenced by id via
            # rule.messageStrings[id].text (SARIF message string reuse).
            msg = res.get("message", {}) or {}
            msg_text = msg.get("text", "")
            if not msg_text and msg.get("id"):
                rule = rules_by_id.get(rid, {})
                mstrings = rule.get("messageStrings", {}) or {}
                entry = mstrings.get(msg["id"], {}) or {}
                msg_text = entry.get("text", "")
            if not msg_text and rid:
                msg_text = rid  # fall back to the rule name itself

            findings.append({
                "ruleId": rid,
                "cwes": cwes,
                "uri": uri,
                "path_key": path_key(uri),
                "line": line,
                "message": msg_text,
                "vulnId": (res.get("properties", {}) or {}).get("vulnId"),
                "raw_uri": uri,
            })
    return findings


def loc_match(ref, act, tolerance, require_cwe):
    if ref["path_key"] != act["path_key"]:
        return False
    if ref["line"] is None or act["line"] is None:
        # can't compare lines; fall back to file-only match
        line_ok = True
    else:
        line_ok = abs(int(ref["line"]) - int(act["line"])) <= tolerance
    if not line_ok:
        return False
    if require_cwe:
        if not (ref["cwes"] & act["cwes"]):
            return False
    return True


def cwe_match(ref, act, same_file=True):
    """Match by CWE overlap. By default also require the same source file so a
    finding of class X in file A cannot 'claim' a planted class-X issue in
    file B. Use --cwe-any-file to disable the file constraint."""
    if same_file and ref["path_key"] != act["path_key"]:
        return False
    return bool(ref["cwes"] & act["cwes"])


def greedy_match(refs, acts, matcher):
    """One-to-one matching. Returns (matches, missed_refs, extra_acts).

    Two-pass to avoid a greedy finding 'stealing' a reference that another
    finding matches more tightly:
      pass 1 = exact-line matches (line delta 0) first,
      pass 2 = remaining (tolerance / cwe) matches.
    This prevents duplicate tool findings near a sink from leaving a
    genuinely-detected planted vuln counted as missed.
    """
    used_act = set()
    used_ref = set()
    matches = []

    def line_delta(ref, act):
        if ref["line"] is None or act["line"] is None:
            return 10 ** 9
        return abs(int(ref["line"]) - int(act["line"]))

    # Pass 1: prefer the closest-line match for each reference.
    for ri, ref in enumerate(refs):
        best_ai, best_d = None, None
        for ai, act in enumerate(acts):
            if ai in used_act:
                continue
            if matcher(ref, act):
                d = line_delta(ref, act)
                if best_d is None or d < best_d:
                    best_ai, best_d = ai, d
        if best_ai is not None:
            matches.append((ri, best_ai))
            used_act.add(best_ai)
            used_ref.add(ri)

    missed = [refs[i] for i in range(len(refs)) if i not in used_ref]
    extra = [acts[i] for i in range(len(acts)) if i not in used_act]
    return matches, missed, extra


def categorize_extra(extra, refs, tolerance, src_prefixes=("src/",)):
    """Split unmatched tool findings into meaningful buckets:

      - duplicate : lands within tolerance of a PLANTED line already matched
                    (i.e. a second rule firing on the same real vuln)
      - dependency: no file / no line (SCA / vulnerable-dependency findings)
      - non_source: finding in a file outside the app source tree
                    (e.g. the checker script itself, build files, tests)
      - false_pos : everything else (a genuine extra finding in app source)
    """
    planted_lines = {}
    for r in refs:
        if r["line"] is not None:
            planted_lines.setdefault(r["path_key"], []).append(int(r["line"]))

    def near_planted(e):
        if e["line"] is None:
            return False
        for pl in planted_lines.get(e["path_key"], []):
            if abs(pl - int(e["line"])) <= tolerance:
                return True
        return False

    def in_source(e):
        u = (e["path_key"] or "")
        # heuristic: real app source lives under a java package path
        return (".java" in u) and ("/vulnapp/" in u or "src/" in (e["raw_uri"] or ""))

    buckets = {"duplicate": [], "dependency": [], "non_source": [], "false_pos": []}
    for e in extra:
        if not e["path_key"] or e["line"] is None:
            buckets["dependency"].append(e)
        elif not in_source(e):
            buckets["non_source"].append(e)
        elif near_planted(e):
            buckets["duplicate"].append(e)
        else:
            buckets["false_pos"].append(e)
    return buckets


def main():
    ap = argparse.ArgumentParser(
        description="Compare SAST SARIF output vs reference ground-truth SARIF.")
    ap.add_argument("-r", "--reference", required=True, help="reference SARIF (ground truth)")
    ap.add_argument("-a", "--actual", required=True, help="SAST tool SARIF output")
    ap.add_argument("--match", choices=["location", "cwe"], default="location",
                    help="matching strategy (default: location)")
    ap.add_argument("--tolerance", type=int, default=3,
                    help="line tolerance for location match (default: 3)")
    ap.add_argument("--require-cwe", action="store_true",
                    help="in location mode, also require CWE to match")
    ap.add_argument("--cwe-any-file", action="store_true",
                    help="in cwe mode, match across files (ignore file, class only)")
    ap.add_argument("--json", metavar="PATH", help="write full report as JSON to PATH")
    ap.add_argument("--fail-under", type=float, default=None,
                    help="exit non-zero if recall (0-100%%) is below this value")
    ap.add_argument("--quiet", action="store_true", help="only print the summary line")
    args = ap.parse_args()

    ref_sarif = load_sarif(args.reference)
    act_sarif = load_sarif(args.actual)

    refs = parse_results(ref_sarif)
    acts = parse_results(act_sarif)

    if not refs:
        eprint("ERROR: reference SARIF has no results.")
        sys.exit(2)

    if args.match == "cwe":
        matcher = lambda ref, act: cwe_match(ref, act, same_file=not args.cwe_any_file)
    else:
        matcher = lambda ref, act: loc_match(ref, act, args.tolerance, args.require_cwe)

    matches, missed, extra = greedy_match(refs, acts, matcher)
    buckets = categorize_extra(extra, refs, args.tolerance)

    n_ref = len(refs)
    n_act = len(acts)
    tp = len(matches)
    fn = len(missed)
    n_dup = len(buckets["duplicate"])
    n_dep = len(buckets["dependency"])
    n_nonsrc = len(buckets["non_source"])
    fp = len(buckets["false_pos"])          # true false positives only
    fp_all = len(extra)

    recall = 100.0 * tp / n_ref if n_ref else 0.0
    # Precision uses TP against TP + genuine false positives (duplicates,
    # dependency/SCA findings and non-source findings are excluded).
    precision = 100.0 * tp / (tp + fp) if (tp + fp) else 0.0
    # Raw precision counts every unmatched finding as a FP (old behaviour).
    precision_raw = 100.0 * tp / n_act if n_act else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    report = {
        "reference_file": args.reference,
        "actual_file": args.actual,
        "match_strategy": args.match,
        "tolerance": args.tolerance if args.match == "location" else None,
        "require_cwe": args.require_cwe if args.match == "location" else None,
        "reference_count": n_ref,
        "actual_count": n_act,
        "matched": tp,
        "missed": fn,
        "extra_total": fp_all,
        "false_positives": fp,
        "duplicates": n_dup,
        "dependency_findings": n_dep,
        "non_source_findings": n_nonsrc,
        "recall_pct": round(recall, 2),
        "precision_pct": round(precision, 2),
        "precision_raw_pct": round(precision_raw, 2),
        "f1_pct": round(f1, 2),
        "matched_details": [
            {
                "ref_vulnId": refs[ri].get("vulnId"),
                "ref": f"{refs[ri]['path_key']}:{refs[ri]['line']}",
                "ref_cwes": sorted(refs[ri]["cwes"]),
                "actual": f"{acts[ai]['path_key']}:{acts[ai]['line']}",
                "actual_ruleId": acts[ai]["ruleId"],
            } for ri, ai in matches
        ],
        "missed_details": [
            {
                "vulnId": m.get("vulnId"),
                "location": f"{m['path_key']}:{m['line']}",
                "cwes": sorted(m["cwes"]),
                "message": m["message"],
            } for m in missed
        ],
        "extra_by_category": {
            cat: [
                {
                    "location": f"{e['path_key']}:{e['line']}",
                    "ruleId": e["ruleId"],
                    "cwes": sorted(e["cwes"]),
                    "message": e["message"],
                } for e in items
            ] for cat, items in buckets.items()
        },
    }

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    if not args.quiet:
        print("=" * 64)
        print(" SAST SARIF Comparison Report")
        print("=" * 64)
        print(f" Reference : {args.reference}  ({n_ref} planted vulns)")
        print(f" Actual    : {args.actual}  ({n_act} findings)")
        print(f" Strategy  : {args.match}"
              + (f" (tolerance={args.tolerance}, require_cwe={args.require_cwe})"
                 if args.match == "location" else ""))
        print("-" * 64)
        print(f" Matched (TP)      : {tp}")
        print(f" Missed  (FN)      : {fn}")
        print(f" False positives   : {fp}")
        print(f" Extra (total)     : {fp_all}"
              f"  = {fp} FP + {n_dup} dup + {n_dep} dep/SCA + {n_nonsrc} non-source")
        print(f" Recall            : {recall:6.2f}%   ({tp}/{n_ref} planted found)")
        print(f" Precision         : {precision:6.2f}%   (TP / (TP+FP), excl. dup/dep/non-src)")
        print(f" Precision (raw)   : {precision_raw:6.2f}%   (TP / all tool findings)")
        print(f" F1 score          : {f1:6.2f}%")
        print("-" * 64)

        if missed:
            print(f" MISSED ({len(missed)}):")
            for m in sorted(missed, key=lambda x: x.get("vulnId") or ""):
                print(f"   - {m.get('vulnId') or '?'}  {m['path_key']}:{m['line']}  "
                      f"[{','.join(sorted(m['cwes'])) or 'no-cwe'}]")
        else:
            print(" MISSED: none — all planted vulnerabilities detected 🎯")

        def dump(cat, label):
            items = buckets[cat]
            if not items:
                return
            print(f" {label} ({len(items)}):")
            for e in items[:50]:
                print(f"   + {e['path_key']}:{e['line']}  {e['ruleId']}  "
                      f"[{','.join(sorted(e['cwes'])) or 'no-cwe'}]")
            if len(items) > 50:
                print(f"   ... and {len(items) - 50} more")

        dump("false_pos", "FALSE POSITIVES (extra findings in app source)")
        dump("duplicate", "DUPLICATES (extra rule firing on an already-found vuln)")
        dump("dependency", "DEPENDENCY / SCA findings (no code location)")
        dump("non_source", "NON-SOURCE findings (outside app src, e.g. checker/build)")
        print("=" * 64)

    print(f"SUMMARY matched={tp}/{n_ref} recall={recall:.2f}% "
          f"precision={precision:.2f}% f1={f1:.2f}%")

    if args.fail_under is not None and recall < args.fail_under:
        eprint(f"FAIL: recall {recall:.2f}% < threshold {args.fail_under:.2f}%")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
