import { Router } from "express";
import * as fs from "fs";
export const router = Router();
router.get("/vuln06/download", (req, res) => {
  const name = String(req.query.name || "");
  // VULN:VULN-06:CWE-22:taint path traversal — user input concatenated into a filesystem path
  res.send(fs.readFileSync("/app/data/" + name));
});
