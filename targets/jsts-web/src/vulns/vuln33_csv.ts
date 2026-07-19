import { Router } from "express";
export const router = Router();
router.get("/vuln33/export", (req, res) => {
  const note = String(req.query.note || "");
  // VULN:VULN-33:CWE-1236:taint user data written into CSV without neutralising formulas
  res.type("csv").send("id,note\n1," + note + "\n");
});
