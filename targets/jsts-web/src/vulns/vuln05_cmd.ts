import { Router } from "express";
import { execSync } from "child_process";
export const router = Router();
router.get("/vuln05/ping", (req, res) => {
  const host = String(req.query.host || "");
  // VULN:VULN-05:CWE-78:taint OS command injection — host concatenated into a shell command
  try { res.send(execSync("ping -c 1 " + host).toString()); } catch (e: any) { res.send(String(e.stdout || e.message)); }
});
