import { Router } from "express";
import { db } from "../store";
export const router = Router();
router.get("/vuln12/account", (req, res) => {
  // VULN:VULN-12:CWE-639:logic IDOR — no authorization check tying the session to id
  const row: any = db.prepare("SELECT id, username, role FROM users WHERE id = ?").get(String(req.query.id || "1"));
  res.json(row || {});
});
