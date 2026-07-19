import { Router } from "express";
export const router = Router();
router.get("/vuln32/calc", (req, res) => {
  const expr = String(req.query.expr || "");
  // VULN:VULN-32:CWE-95:taint code injection — user input passed to eval()
  res.send("result: " + String(eval(expr)));
});
