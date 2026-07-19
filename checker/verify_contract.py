#!/usr/bin/env python3
"""verify_contract.py — enforce the target contract for a vulnerable target.

Every planted vulnerability must be in sync across four sources of truth:
  1. a  VULN:VULN-xx:CWE-nnn:class  marker in the source
  2. an entry in the VulnCatalog (dashboard)          [java-web only]
  3. a reference.sarif finding
  4. an exploit step in exploits/exploit_all.py

Drift between them silently corrupts FP/FN scoring, so this fails (exit 1) on
any mismatch. Language-agnostic where possible; catalog/exploit parsing is
best-effort per target.

Usage: python3 checker/verify_contract.py targets/java-web
"""
import json, os, re, sys

def ids_from_markers(root):
    ids = {}
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "target", "node_modules", "build")]
        for f in fn:
            if os.path.splitext(f)[1] not in (".java", ".kt", ".js", ".ts", ".py",
                    ".sql", ".html", ".properties", ".c", ".cpp", ".h", ".swift", ".xml"):
                continue
            try:
                for i, line in enumerate(open(os.path.join(dp, f), encoding="utf-8", errors="replace"), 1):
                    m = re.search(r"VULN:(VULN-\d+):(CWE-\d+)(?::([a-z]+))?", line)
                    if m:
                        ids.setdefault(m.group(1), []).append((os.path.relpath(os.path.join(dp, f), root), i, m.group(3) or "unknown"))
            except OSError:
                pass
    return ids

def ids_from_catalog(root):
    cat = None
    for dp, _, fn in os.walk(root):
        for f in fn:
            if f in ("VulnCatalog.java", "VulnCatalog.kt", "catalog.py", "catalog.ts"):
                cat = os.path.join(dp, f)
    if not cat:
        return None
    txt = open(cat, encoding="utf-8").read()
    # Java/Kotlin use Entry("VULN-xx",..; Python catalog.py uses ("VULN-xx",..
    return set(re.findall(r'[(\[]\s*"(VULN-\d+)"', txt))

def ids_from_exploits(root):
    p = os.path.join(root, "exploits", "exploit_all.py")
    if not os.path.isfile(p):
        return None
    txt = open(p, encoding="utf-8").read()
    return {f"VULN-{n}" for n in re.findall(r"def x(\d{2})\(", txt)}

def ids_from_reference(root):
    p = os.path.join(root, "reference.sarif")
    if not os.path.isfile(p):
        return None
    j = json.load(open(p))
    out = set()
    for run in j.get("runs", []):
        for r in run.get("results", []):
            vid = (r.get("properties") or {}).get("vulnId")
            if vid:
                out.add(vid)
    return out

def main():
    if len(sys.argv) < 2:
        print("usage: verify_contract.py <target-dir>", file=sys.stderr); sys.exit(2)
    root = sys.argv[1]
    markers = ids_from_markers(root)
    marker_ids = set(markers)
    catalog = ids_from_catalog(root)
    exploits = ids_from_exploits(root)
    reference = ids_from_reference(root)

    print(f"contract check: {root}")
    print(f"  markers  : {len(marker_ids)} ids")
    print(f"  catalog  : {len(catalog) if catalog is not None else 'n/a'}")
    print(f"  exploits : {len(exploits) if exploits is not None else 'n/a'}")
    print(f"  reference: {len(reference) if reference is not None else 'n/a'}")

    problems = []
    sources = {"catalog": catalog, "exploits": exploits, "reference": reference}
    universe = set(marker_ids)
    for s in sources.values():
        if s: universe |= s

    for vid in sorted(universe):
        where = []
        if vid in marker_ids: where.append("marker")
        for name, s in sources.items():
            if s is not None and vid in s: where.append(name)
        expected = ["marker"] + [n for n, s in sources.items() if s is not None]
        missing = [e for e in expected if e not in where]
        if missing:
            problems.append(f"  {vid}: present in {where}, MISSING from {missing}")

    # markers whose detection class is unknown
    unknown = [vid for vid, locs in markers.items() if all(c == "unknown" for _, _, c in locs)]
    if unknown:
        problems.append(f"  markers with no detection class: {sorted(unknown)}")

    if problems:
        print("DRIFT DETECTED:")
        print("\n".join(problems))
        sys.exit(1)
    print(f"OK — {len(universe)} vulnerabilities in sync across all sources.")
    sys.exit(0)

if __name__ == "__main__":
    main()
