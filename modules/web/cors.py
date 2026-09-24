"""cors — CORS misconfiguration probe (origin reflection, null, wildcards)"""
from core.http import HttpClient

EVIL = "https://omni-cors-canary.example"
class Cors:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        findings = []
        for origin in [EVIL, "null", "https://attacker.com"]:
            r = http.get(session.target, headers={"Origin": origin})
            if not r: continue
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","")
            if acao:
                print(f"  origin={origin} -> ACAO={acao} ACAC={acac}")
                if acao == origin or acao == "*":
                    sev = "high" if acac.lower() == "true" and acao != "*" else "medium"
                    findings.append({"origin":origin,"acao":acao,"acac":acac})
                    logger.finding("cors", sev, f"origin={origin} acao={acao} creds={acac}")
        print(f"[cors] done: {len(findings)}")
        return {"findings": findings}
