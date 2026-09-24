"""csp — Content-Security-Policy analysis (weak policies, bypasses)"""
import re
from core.http import HttpClient

class Csp:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        r = http.get(session.target)
        if not r: return {}
        csp = r.headers.get("Content-Security-Policy","")
        issues = []
        if not csp:
            issues.append("no_csp")
        else:
            if "unsafe-inline" in csp: issues.append("unsafe-inline")
            if "unsafe-eval" in csp:   issues.append("unsafe-eval")
            if "*" in csp:             issues.append("wildcard")
            if "data:" in csp:         issues.append("data_uri_allowed")
            if "http:" in csp:         issues.append("http_allowed")
            if not re.search(r"default-src", csp): issues.append("no_default_src")
            if not re.search(r"script-src", csp):  issues.append("no_script_src")
        print(f"[csp] {csp or 'none'}")
        for i in issues:
            print(f"  [!] {i}")
            logger.finding("csp", "low", i)
        # other security headers
        hdr_checks = ["Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options",
                      "Referrer-Policy","Permissions-Policy"]
        missing = [h for h in hdr_checks if h not in r.headers]
        for m in missing:
            logger.finding("missing_header", "low", m)
        return {"csp": csp, "issues": issues, "missing_headers": missing}
