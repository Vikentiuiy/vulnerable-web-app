import { Router } from "express";
export const router = Router();
function merge(target: any, src: any): any {
  for (const k in src) {
    if (src[k] && typeof src[k] === "object") { if (!target[k]) target[k] = {}; merge(target[k], src[k]); }
    else target[k] = src[k];
  }
  return target;
}
router.post("/vuln43/merge", (req, res) => {
  const dst: any = {};
  // VULN:VULN-43:CWE-1321:taint prototype pollution — recursive merge of attacker-controlled keys
  merge(dst, req.body);
  res.json({ polluted: ({} as any).polluted || false });
});
