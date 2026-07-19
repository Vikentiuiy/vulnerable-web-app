import { Router } from "express";
import * as crypto from "crypto";
import { db } from "../store";
export const router = Router();
router.post("/vuln29/register", (req, res) => {
  const role = String(req.body.role || "user");
  const h = crypto.createHash("md5").update(String(req.body.password || "")).digest("hex");
  // VULN:VULN-29:CWE-915:logic mass assignment — caller-controlled role bound directly
  db.prepare("INSERT INTO users(username,password,role,bio,ssn) VALUES(?,?,?,'','000-00-0000')").run(String(req.body.username || ""), h, role);
  res.json({ status: "registered", role });
});
