import { Router } from "express";
import * as crypto from "crypto";
import { db } from "../store";
export const router = Router();
router.post("/vuln02/login", (req, res) => {
  const u = String(req.body.username || "");
  const h = crypto.createHash("md5").update(String(req.body.password || "")).digest("hex");
  // VULN:VULN-02:CWE-89:taint SQL injection in authentication (login bypass)
  const row: any = db.prepare("SELECT username, role FROM users WHERE username = '" + u + "' AND password = '" + h + "'").get();
  res.json(row ? { status: "ok", user: row.username } : { status: "invalid" });
});
