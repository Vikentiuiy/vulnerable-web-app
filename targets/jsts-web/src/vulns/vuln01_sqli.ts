import { Router } from "express";
import { db } from "../store";
export const router = Router();
router.get("/vuln01/search", (req, res) => {
  const q = String(req.query.q || "");
  // VULN:VULN-01:CWE-89:taint SQL injection in product search
  const rows = db.prepare("SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'").all();
  res.json(rows);
});
