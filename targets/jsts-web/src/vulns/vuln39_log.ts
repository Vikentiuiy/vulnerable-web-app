import { Router } from "express";
export const router = Router();
router.get("/vuln39/note", (req, res) => {
  const text = String(req.query.text || "");
  // VULN:VULN-39:CWE-117:taint user input logged without neutralising CR/LF
  console.log("[audit] user note: " + text);
  res.json({ logged: true });
});
