import { Router } from "express";
export const router = Router();
router.get("/vuln24/redirect", (req, res) => {
  // VULN:VULN-24:CWE-601:taint open redirect — unvalidated redirect target
  res.redirect(String(req.query.url || ""));
});
