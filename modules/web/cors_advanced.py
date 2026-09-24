"""cors_advanced — advanced CORS: subdomain reflection, null, regex bypass"""
from core.http import HttpClient

class CorsAdvanced:
    def run(self, session, logger):
        target = session.target
        from urllib.parse import urlparse
        u = urlparse(target)
        domain = u.hostname or ""
        parts = domain.split(".")
        base_dom = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        evil_origins = [
            f"https://{base_dom}.attacker.example",
            f"https://attacker.{base_dom}",
            f"https://{base_dom}x",
            f"https://x{base_dom}",
            f"https://{base_dom}.evil.example",
            f"https://sub.{base_dom}",
            f"https://{base_dom}:4443",
            f"http://{base_dom}",
            "null",
            "https://null",
            "https://localhost",
            "https://127.0.0.1",
            "file://",
            "https://attacker.example",
            f"https://{base_dom}%2eattacker.example",
            f"https://attacker.example%2e{base_dom}",
        ]

        http = HttpClient(session, logger)
        findings = []
        for origin in evil_origins:
            r = http.get(target, headers={"Origin":origin})
            if not r: continue
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","")
            if not acao: continue
            reflected = acao == origin or acao == "*" or base_dom in acao
            if reflected and acao != "*":
                sev = "critical" if acac.lower() == "true" else "high"
                findings.append({"origin":origin,"acao":acao,"creds":acac})
                print(f"  [!] {origin} -> ACAO={acao} creds={acac}")
                logger.finding("cors_reflect", sev, f"{origin} -> {acao} creds={acac}")
            elif acao == "*" and acac.lower() == "true":
                findings.append({"origin":origin,"acao":"*","creds":"true"})
                logger.finding("cors_wildcard_creds","high","wildcard + credentials")
                print(f"  [!] wildcard + credentials")

        print(f"[cors_advanced] {len(findings)} findings")
        return {"findings": findings}
