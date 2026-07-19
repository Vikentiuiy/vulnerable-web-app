import { Router } from "express";
export const router = Router();
const store: Record<string, string> = {};
router.post("/vuln04/save", (req, res) => { store[String(req.body.id)] = String(req.body.bio || ""); res.json({ status: "saved" }); });
router.get("/vuln04/show", (req, res) => {
  const bio = store[String(req.query.id)] || "";
  // VULN:VULN-04:CWE-79:taint stored XSS: persisted bio rendered unescaped
  res.type("html").send("<html><body><div>" + bio + "</div></body></html>");
});
