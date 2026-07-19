#!/usr/bin/env python3
"""Compare PT AI SARIF outputs across scan profiles (ablation study).

Given N profile SARIFs, prints:
  - per-profile finding count + distinct rule types
  - the union rule/location matrix (which profile fired which finding)
  - incremental contribution of each profile over `default`
"""
import json, sys, os
from collections import OrderedDict

def load(path):
    j = json.load(open(path))
    out = []
    for run in j.get("runs", []):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            rule = rules.get(rid, {})
            name = rule.get("name") or (rule.get("shortDescription", {}) or {}).get("text") or rid
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", "")
            short = "/".join([p for p in uri.split("/") if p][-2:])
            out.append((str(name), short, line))
    return out

def key(f):
    return (f[0], f[1], f[2])

def main(paths):
    profiles = OrderedDict()
    for p in paths:
        name = os.path.splitext(os.path.basename(p))[0]
        if os.path.exists(p):
            profiles[name] = load(p)
        else:
            profiles[name] = None

    print("=" * 70)
    print(" PT AI SCAN-PROFILE ABLATION")
    print("=" * 70)
    print(f'{"profile":12} {"findings":>9} {"rule types":>11}')
    print("-" * 70)
    for name, f in profiles.items():
        if f is None:
            print(f"{name:12} {'MISSING':>9}")
            continue
        print(f"{name:12} {len(f):>9} {len(set(x[0] for x in f)):>11}")

    # union matrix
    all_keys = []
    seen = set()
    for f in profiles.values():
        if not f: continue
        for x in f:
            if key(x) not in seen:
                seen.add(key(x)); all_keys.append(x)
    names = [n for n, f in profiles.items() if f is not None]
    present = {n: set(key(x) for x in profiles[n]) for n in names}

    print("\n" + "=" * 70)
    print(" FINDING x PROFILE MATRIX  (✓ = fired)")
    print("=" * 70)
    hdr = " " * 46 + "".join(f"{n[:6]:>8}" for n in names)
    print(hdr)
    all_keys.sort(key=lambda x: (x[0], x[1]))
    for x in all_keys:
        cells = "".join(f'{("  ✓" if key(x) in present[n] else "  ·"):>8}' for n in names)
        label = f"{x[0][:30]:30} {x[1][:14]:14}:{x[2]}"
        print(f"{label:46}{cells}")

    # incremental over default
    if "default" in present:
        base = present["default"]
        print("\n" + "=" * 70)
        print(" INCREMENTAL CONTRIBUTION over `default`")
        print("=" * 70)
        for n in names:
            if n == "default": continue
            added = present[n] - base
            removed = base - present[n]
            print(f"\n--- {n}: +{len(added)} new, -{len(removed)} lost (total {len(present[n])} vs {len(base)}) ---")
            byrule = {}
            for x in added:
                byrule.setdefault(x[0], []).append(f"{x[1]}:{x[2]}")
            for r in sorted(byrule):
                print(f"   + {r}  ({len(byrule[r])}):  {', '.join(byrule[r][:6])}")

if __name__ == "__main__":
    main(sys.argv[1:])
