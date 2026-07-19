import { Router } from "express";
export const router = Router();
router.get("/vuln17/login", (req, res) => {
  const token = Math.random().toString(16).slice(2);
  // VULN:VULN-17:CWE-614:config auth cookie set without HttpOnly/Secure flags
  res.cookie("auth", token, { httpOnly: false, secure: false });
  res.json({ status: "ok", token });
});
