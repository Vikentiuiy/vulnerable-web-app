import { Router } from "express";
export const router = Router();
router.get("/vuln40/setsession", (req, res) => {
  const sid = String(req.query.sid || "");
  // VULN:VULN-40:CWE-384:logic session id taken from the request and set as-is
  res.cookie("session", sid);
  res.json({ session: sid });
});
