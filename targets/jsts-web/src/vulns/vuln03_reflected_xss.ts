import { Router } from "express";
export const router = Router();
router.get("/vuln03/echo", (req, res) => {
  const q = String(req.query.q || "");
  // VULN:VULN-03:CWE-79:taint reflected XSS: input echoed into HTML unescaped
  res.type("html").send("<html><body><h3>You searched for: " + q + "</h3></body></html>");
});
