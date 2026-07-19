import express from "express";
import { seed } from "./store";
import { TRACKER } from "./harness/tracker";
import * as detector from "./harness/detector";

// Static router imports so the SAST can see every Express entry point (1:1).
import { router as v01 } from "./vulns/vuln01_sqli";
import { router as v02 } from "./vulns/vuln02_sqli_login";
import { router as v03 } from "./vulns/vuln03_reflected_xss";
import { router as v04 } from "./vulns/vuln04_stored_xss";
import { router as v05 } from "./vulns/vuln05_cmd";
import { router as v06 } from "./vulns/vuln06_path";
import { router as v10 } from "./vulns/vuln10_ssrf";
import { router as v11 } from "./vulns/vuln11_ssn";
import { router as v12 } from "./vulns/vuln12_idor";
import { router as v13 } from "./vulns/vuln13_hash";
import { router as v16 } from "./vulns/vuln16_verbose";
import { router as v17 } from "./vulns/vuln17_cookie";
import { router as v18 } from "./vulns/vuln18_token";
import { router as v24 } from "./vulns/vuln24_redirect";
import { router as v29 } from "./vulns/vuln29_mass_assign";
import { router as v32 } from "./vulns/vuln32_eval";
import { router as v33 } from "./vulns/vuln33_csv";
import { router as v34 } from "./vulns/vuln34_cors";
import { router as v38 } from "./vulns/vuln38_redos";
import { router as v39 } from "./vulns/vuln39_log";
import { router as v40 } from "./vulns/vuln40_session";
import { router as v43 } from "./vulns/vuln43_proto_pollution";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.text({ type: ["text/*", "application/xml"] }));

seed();

const routers = [v01, v02, v03, v04, v05, v06, v10, v11, v12, v13, v16, v17,
  v18, v24, v29, v32, v33, v34, v38, v39, v40, v43];
routers.forEach((r) => app.use(r));

detector.install(app);

app.get("/api/status", (_req, res) => res.json(TRACKER.snapshot()));
// VULN:VULN-35:CWE-1021:config no X-Frame-Options / CSP frame-ancestors set anywhere -> clickjacking
app.get("/", (_req, res) => res.json({ app: "vuln-jsts-web", vulns: TRACKER.snapshot().total, dashboard: "/api/status" }));

app.listen(8083, () => console.log("vuln-jsts-web on :8083"));
