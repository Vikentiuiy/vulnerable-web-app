import { Router } from "express";
export const router = Router();
// VULN:VULN-38:CWE-1333:logic catastrophically-backtracking regex applied to user input
const EVIL = /^(.*a){12}$/;
router.get("/vuln38/validate", (req, res) => {
  const email = String(req.query.email || "").slice(0, 30);
  const t0 = Date.now();
  const ok = EVIL.test(email);
  res.json({ valid: ok, ms: Date.now() - t0 });
});
