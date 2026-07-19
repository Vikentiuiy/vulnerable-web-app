// HARNESS (out of scan scope). The ONLY instrumentation point: an Express
// middleware that observes each request/response and marks the tracker when a
// genuinely-malicious payload hits a planted endpoint. Keeps vuln routers clean.
import { Express, Request, Response, NextFunction } from "express";
import { TRACKER } from "./tracker";

let v30 = 0;

function P(req: Request, name: string): string {
  return (req.query[name] as string) || (req.body && req.body[name]) || "";
}
function has(s: string, ...subs: string[]): boolean { return subs.some((x) => (s || "").toLowerCase().includes(x.toLowerCase())); }

export function install(app: Express): void {
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (!req.path.startsWith("/vuln")) return next();
    const orig = res.send.bind(res);
    let cap = "";
    (res as any).send = (body: any) => { cap = typeof body === "string" ? body : JSON.stringify(body); return orig(body); };
    res.on("finish", () => { try { inspect(req, res, cap); } catch (e) { /* ignore */ } });
    next();
  });
}

function inspect(req: Request, res: Response, body: string): void {
  const path = req.path;
  const raw = typeof req.body === "string" ? req.body : JSON.stringify(req.body || {});
  const m = (id: string, d: string) => TRACKER.mark(id, d);
  if (path.startsWith("/vuln01") && /union|select|--|'|information_schema/i.test(P(req, "q"))) m("VULN-01", "SQLi payload processed");
  if (path.startsWith("/vuln02") && has(P(req, "username"), "'", "--")) m("VULN-02", "auth bypass payload");
  if (path.startsWith("/vuln03") && /<script|onerror=|<img|<svg/i.test(P(req, "q"))) m("VULN-03", "reflected XSS echoed");
  if (path.startsWith("/vuln04/save") && /<script|onerror=|<img|<svg/i.test(P(req, "bio"))) m("VULN-04", "stored XSS persisted");
  if (path.startsWith("/vuln05") && /[;|&`$\n]/.test(P(req, "host"))) m("VULN-05", "command injection");
  if (path.startsWith("/vuln06") && (P(req, "name").includes("..") || P(req, "name").startsWith("/"))) m("VULN-06", "path traversal");
  if (path.startsWith("/vuln10") && P(req, "url")) m("VULN-10", "SSRF fetched URL");
  if (path.startsWith("/vuln11") && /\d{3}-\d{2}-\d{4}/.test(body)) m("VULN-11", "SSN exposed");
  if (path.startsWith("/vuln12")) m("VULN-12", "object accessed w/o authz");
  if (path.startsWith("/vuln13")) m("VULN-13", "unsalted MD5 hashing");
  if (path.startsWith("/vuln16") && /error|sqlite|at object|at \//i.test(body)) m("VULN-16", "verbose error/stack leaked");
  if (path.startsWith("/vuln17")) { const sc = String(res.getHeader("Set-Cookie") || ""); if (sc.includes("auth=") && !/httponly/i.test(sc)) m("VULN-17", "cookie without HttpOnly"); }
  if (path.startsWith("/vuln18") && P(req, "user")) m("VULN-18", "predictable token issued");
  if (path.startsWith("/vuln24") && /^(https?:)?\/\//i.test(P(req, "url"))) m("VULN-24", "open redirect");
  if (path.startsWith("/vuln29") && P(req, "role") && P(req, "role").toLowerCase() !== "user") m("VULN-29", "role escalated");
  if (path.startsWith("/vuln32") && P(req, "expr")) m("VULN-32", "eval of user expression");
  if (path.startsWith("/vuln33") && /^[=+\-@]/.test(P(req, "note"))) m("VULN-33", "CSV formula injected");
  if (path.startsWith("/vuln34") && req.headers.origin) m("VULN-34", "CORS reflected origin");
  if (path.startsWith("/vuln38") && P(req, "email").length > 20) m("VULN-38", "ReDoS input");
  if (path.startsWith("/vuln39") && /[\r\n]/.test(P(req, "text"))) m("VULN-39", "CRLF log injection");
  if (path.startsWith("/vuln40") && P(req, "sid")) m("VULN-40", "session fixation");
  if (path.startsWith("/vuln43") && /__proto__|constructor|prototype/.test(raw)) m("VULN-43", "prototype pollution payload");
}
