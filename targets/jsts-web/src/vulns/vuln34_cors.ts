import { Router } from "express";
export const router = Router();
router.get("/vuln34/data", (req, res) => {
  const origin = req.headers.origin;
  if (origin) {
    // VULN:VULN-34:CWE-942:config arbitrary Origin reflected + credentials allowed
    res.header("Access-Control-Allow-Origin", String(origin));
    res.header("Access-Control-Allow-Credentials", "true");
  }
  res.json({ secret: "account-balance-42000" });
});
