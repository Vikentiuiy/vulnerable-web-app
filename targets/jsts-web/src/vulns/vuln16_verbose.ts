import { Router } from "express";
import { db } from "../store";
export const router = Router();
router.get("/vuln16/lookup", (req, res) => {
  try { db.prepare("SELECT * FROM users WHERE id = " + String(req.query.id || "")).get(); res.json({ status: "ok" }); }
  catch (e: any) {
    // VULN:VULN-16:CWE-209:logic full error/stack returned to the client
    res.status(500).send("error:\n" + (e.stack || e.message));
  }
});
