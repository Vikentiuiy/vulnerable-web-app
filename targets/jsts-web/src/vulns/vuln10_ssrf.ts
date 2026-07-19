import { Router } from "express";
import axios from "axios";
export const router = Router();
router.get("/vuln10/fetch", async (req, res) => {
  const url = String(req.query.url || "");
  // VULN:VULN-10:CWE-918:taint SSRF — server fetches an arbitrary user-supplied URL
  try { const r = await axios.get(url, { timeout: 4000 }); res.send(typeof r.data === "string" ? r.data : JSON.stringify(r.data)); }
  catch (e: any) { res.send("error: " + e.message); }
});
