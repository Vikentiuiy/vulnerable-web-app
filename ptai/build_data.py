#!/usr/bin/env python3
"""Score every tool/profile SARIF against each target's reference and emit:
  - results/report_data.json  (consumed by ptai/gen_report.py)
  - benchmark/engine-recall.csv  (long-format, committed)

Profiles: default (=pure taint engine), pm, config, max, refconfig (customer
b63d419a default). Plus Semgrep. jsts also gets a compiled-JS engine figure.
"""
import csv, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "checker"))
import sast_checker as sc

TARGETS = ["java-web", "python-web", "jsts-web", "kotlin-web", "cpp", "sql", "sql-app", "swift"]
PROFILES = ["default", "pm", "config", "max", "refconfig"]
JSDIST = "/tmp/claude-0/-root-claude-playground-vulnerable-web-app/47f7793e-deb5-4f97-afc1-6e30165e499a/scratchpad/jsdist"


def score(ref_path, sarif_path):
    if not (os.path.exists(ref_path) and os.path.exists(sarif_path)):
        return None
    try:
        refs = sc.parse_results(sc.load_sarif(ref_path))
        acts = sc.parse_results(sc.load_sarif(sarif_path))
    except Exception:
        return None
    matches, missed, extra = sc.greedy_match(refs, acts, lambda r, a: sc.loc_match(r, a, 3, False, False))
    buckets = sc.categorize_extra(extra, refs, 3)
    tp, fp = len(matches), len(buckets["false_pos"])
    matched_ref = {ri for ri, _ in matches}
    cls = {}
    for i, r in enumerate(refs):
        dc = r.get("dclass") or "unknown"
        cls.setdefault(dc, [0, 0])[1] += 1
        if i in matched_ref:
            cls[dc][0] += 1
    def pct(k): return round(100.0 * cls[k][0] / cls[k][1], 1) if k in cls and cls[k][1] else None
    return {"findings": len(acts), "matched": tp, "fp": fp,
            "recall": round(100.0 * tp / len(refs), 1) if refs else 0,
            "precision": round(100.0 * tp / (tp + fp), 1) if (tp + fp) else None,
            "taint": pct("taint"), "taint_n": cls.get("taint", [0, 0]),
            "pattern": pct("pattern"), "config": pct("config"), "logic": pct("logic")}


data, csv_rows = {}, []
for t in TARGETS:
    ref = os.path.join(ROOT, "targets", t, "reference.sarif")
    e = {"lang": t}
    for prof in PROFILES:
        s = os.path.join(ROOT, "results", f"{t}-{prof}.sarif")
        e["ptai_" + prof] = score(ref, s)
    if t == "jsts-web":
        e["ptai_default_compiled"] = score(f"{JSDIST}/reference.sarif", f"{JSDIST}/compiled.sarif")
    e["semgrep"] = score(ref, os.path.join(ROOT, "results", f"semgrep-{t}.sarif"))
    data[t] = e
    # CSV rows
    for tool, key in [("PT-AI", "ptai_default"), ("PT-AI", "ptai_pm"), ("PT-AI", "ptai_config"),
                      ("PT-AI", "ptai_max"), ("PT-AI", "ptai_refconfig"), ("Semgrep", "semgrep")]:
        r = e.get(key)
        prof = key.replace("ptai_", "").replace("semgrep", "default")
        if r:
            tn = r.get("taint_n") or [0, 0]
            csv_rows.append({"target": t, "tool": tool, "profile": prof,
                             "taint_recall_pct": r.get("taint"), "taint_matched": tn[0], "taint_total": tn[1],
                             "overall_recall_pct": r.get("recall"), "precision_pct": r.get("precision"),
                             "findings": r.get("findings")})

json.dump(data, open(os.path.join(ROOT, "results", "report_data.json"), "w"), indent=2)
os.makedirs(os.path.join(ROOT, "benchmark"), exist_ok=True)
with open(os.path.join(ROOT, "benchmark", "engine-recall.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["target", "tool", "profile", "taint_recall_pct", "taint_matched",
                                      "taint_total", "overall_recall_pct", "precision_pct", "findings"])
    w.writeheader(); w.writerows(csv_rows)
print(f"wrote results/report_data.json and benchmark/engine-recall.csv ({len(csv_rows)} rows)")
