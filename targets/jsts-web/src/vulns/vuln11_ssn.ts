import { Router } from "express";
import { db } from "../store";
export const router = Router();
router.get("/vuln11/profile", (req, res) => {
  const row: any = db.prepare("SELECT username, ssn FROM users WHERE id = ?").get(String(req.query.id || "1"));
  // VULN:VULN-11:CWE-200:logic sensitive data (SSN) returned to any caller
  res.json(row ? { username: row.username, ssn: row.ssn } : {});
});
