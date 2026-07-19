import { Router } from "express";
import * as crypto from "crypto";
export const router = Router();
router.get("/vuln13/hash", (req, res) => {
  // VULN:VULN-13:CWE-327:pattern broken/weak hash (MD5) used for passwords
  res.send(crypto.createHash("md5").update(String(req.query.p || "")).digest("hex"));
});
