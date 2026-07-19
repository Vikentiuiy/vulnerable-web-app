#!/usr/bin/env python3
"""Generate the benchmark report (self-contained HTML) from results/report_data.json.
Re-run after refreshing scans to redeploy the same artifact."""
import json, os, html

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = json.load(open(os.path.join(ROOT, "results", "report_data.json")))

LANGS = ["java-web", "python-web", "jsts-web", "kotlin-web", "sql-app", "cpp", "sql", "swift"]
LABEL = {"java-web": "Java", "python-web": "Python", "jsts-web": "JS/TS", "kotlin-web": "Kotlin",
         "sql-app": "SQL-app", "cpp": "C/C++", "sql": "SQL", "swift": "Swift"}
STACK = {"java-web": "Spring Boot", "python-web": "Flask + SQLite", "jsts-web": "Node/Express + TS",
         "kotlin-web": "Spring Boot + H2", "sql-app": "Flask + MySQL", "cpp": "native + ASAN",
         "sql": "MySQL schema/procs", "swift": "Vapor"}


def taint(entry, key):
    e = (entry or {}).get(key)
    if not e or e.get("taint") is None:
        return None
    return e["taint"]


def taint_n(entry, key):
    e = (entry or {}).get(key)
    if not e:
        return ""
    n = e.get("taint_n") or [0, 0]
    return f"{n[0]}/{n[1]}"


rows = []
for l in LANGS:
    e = DATA.get(l, {})
    # jsts engine: prefer compiled-JS number if the .ts default is 0
    pt_def = taint(e, "ptai_default")
    pt_def_n = taint_n(e, "ptai_default")
    note = ""
    if l == "jsts-web" and e.get("ptai_default_compiled"):
        pt_def = e["ptai_default_compiled"].get("taint")
        pt_def_n = "/".join(map(str, e["ptai_default_compiled"].get("taint_n", [0, 0])))
        note = "compiled JS"
    rows.append({
        "lang": l, "label": LABEL[l], "stack": STACK[l], "note": note,
        "pt_def": pt_def, "pt_def_n": pt_def_n,
        "pt_max": taint(e, "ptai_max"), "pt_max_n": taint_n(e, "ptai_max"),
        "sg": taint(e, "semgrep"), "sg_n": taint_n(e, "semgrep"),
        "pt_prec": ((e.get("ptai_default") or {}).get("precision")),
        "sg_prec": ((e.get("semgrep") or {}).get("precision")),
        "sg_find": ((e.get("semgrep") or {}).get("findings")),
        "abl": {p: taint(e, "ptai_" + p) for p in ["default", "pm", "config", "max"]},
    })

# --- verdict pill per language (who leads on the engine) ---
def verdict(r):
    pt, sg = r["pt_def"], r["sg"]
    if pt is None and sg is None:
        return ("unscored", "muted")
    pt = pt or 0; sg = sg or 0
    if abs(pt - sg) < 5:
        return ("parity", "warn")
    return ("PT AI leads", "ptai") if pt > sg else ("Semgrep leads", "semgrep")


def bar(pct, kind):
    if pct is None:
        return '<div class="bar-row"><span class="bar-na">not analysed</span></div>'
    w = max(pct, 1.5)
    return (f'<div class="bar-row"><div class="bar {kind}" style="width:{w}%"></div>'
            f'<span class="bar-val">{pct:.0f}%</span></div>')


# ---------- module ablation rows ----------
def ablation_block(r):
    steps = [("default", "engine only"), ("pm", "+ PatternMatching"),
             ("config", "+ Configuration"), ("max", "+ Components/SCA")]
    out = []
    for key, lbl in steps:
        v = r["abl"].get(key)
        out.append(
            f'<div class="abl-step"><span class="abl-lbl">{lbl}</span>'
            f'<div class="bar-row"><div class="bar ramp{["default","pm","config","max"].index(key)}" '
            f'style="width:{max((v or 0),1.5)}%"></div>'
            f'<span class="bar-val">{("%.0f%%" % v) if v is not None else "—"}</span></div></div>')
    return "".join(out)


# ---------- HTML ----------
def esc(s): return html.escape(str(s))

hero_rows = ""
for r in rows:
    v, vcls = verdict(r)
    hero_rows += f'''
    <div class="lang-row">
      <div class="lang-head">
        <span class="lang-name">{esc(r["label"])}</span>
        <span class="lang-stack">{esc(r["stack"])}{(" · " + r["note"]) if r["note"] else ""}</span>
        <span class="pill pill-{vcls}">{esc(v)}</span>
      </div>
      <div class="grp">
        <div class="grp-lbl">PT AI <span class="mono">{esc(r["pt_def_n"])}</span></div>{bar(r["pt_def"], "ptai")}
      </div>
      <div class="grp">
        <div class="grp-lbl">Semgrep <span class="mono">{esc(r["sg_n"])}</span></div>{bar(r["sg"], "semgrep")}
      </div>
    </div>'''

table_rows = ""
for r in rows:
    def cell(v): return f'{v:.0f}%' if isinstance(v, (int, float)) else '—'
    table_rows += f'''<tr>
      <td class="l">{esc(r["label"])}<span class="sub">{esc(r["stack"])}</span></td>
      <td class="num">{cell(r["pt_def"])}</td>
      <td class="num">{cell(r["pt_max"])}</td>
      <td class="num sg">{cell(r["sg"])}</td>
      <td class="num dim">{cell(r["pt_prec"])}</td>
      <td class="num dim">{cell(r["sg_prec"])}</td>
    </tr>'''

ablation_rows = ""
for r in rows:
    if all(r["abl"].get(k) is None for k in r["abl"]):
        continue
    ablation_rows += f'''<div class="abl-card">
      <div class="abl-lang">{esc(r["label"])}</div>{ablation_block(r)}</div>'''

TEMPLATE = open(os.path.join(os.path.dirname(__file__), "report_template.html")).read()
out = (TEMPLATE
       .replace("{{HERO_ROWS}}", hero_rows)
       .replace("{{TABLE_ROWS}}", table_rows)
       .replace("{{ABLATION_ROWS}}", ablation_rows))
open(os.path.join(ROOT, "docs", "report.html"), "w").write(out)
print("wrote docs/report.html")
