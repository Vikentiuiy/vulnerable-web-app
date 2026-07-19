import { Router } from "express";
export const router = Router();
router.get("/vuln18/token", (req, res) => {
  // VULN:VULN-18:CWE-330:pattern predictable token from Math.random (not cryptographically secure)
  let t = "";
  for (let i = 0; i < 16; i++) t += Math.floor(Math.random() * 16).toString(16);
  res.send(t);
});
