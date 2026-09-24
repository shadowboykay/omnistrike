"""host_header — Host header injection probe (password reset, cache, SSRF)"""
from core.http import HttpClient

class HostHeader:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        findings = []
        evil = "evil-attacker.example"

        probes = [
            {"Host": evil},
            {"X-Forwarded-Host": evil},
            {"X-Forwarded-Host": f"{evil}, {target}"},
            {"X-Host": evil},
            {"X-Original-Host": evil},
            {"X-Forwarded-Server": evil},
            {"Forwarded": f"host={evil}"},
            {"X-Forwarded-Host": evil, "X-Forwarded-For": "127.0.0.1"},
        ]
        for p in probes:
            r = http.get(target, headers=p)
            if not r: continue
            if evil in r.text or evil in r.headers.get("Location",""):
                findings.append({"header":list(p.keys())[0],"type":"reflect"})
                print(f"  [!] reflected: {list(p.keys())[0]}")
                logger.finding("host_header_reflect","high",str(list(p.keys())[0]))
            if r.status_code in (301,302,303,307,308):
                loc = r.headers.get("Location","")
                if evil in loc:
                    findings.append({"header":list(p.keys())[0],"location":loc})
                    logger.finding("host_header_redirect","high",loc)

        print(f"[host_header] {len(findings)} findings")
        return {"findings": findings}
