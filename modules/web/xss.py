"""xss — reflected XSS scanner: raw echo + context break detection, payloads from core.payloads"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.payloads import get

MARKER = "omni7x9z"

class Xss:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {"q": ["test"]}

        payloads = get("xss", limit=200, mutate_by=1)
        print(f"[xss] {len(payloads)} payloads on {list(params.keys())}")
        findings = []

        # baseline reflection length
        base = http.get(target)
        base_len = len(base.content) if base else 0

        for name in params:
            for p in payloads:
                test = p.replace("alert(1)", f'alert("{MARKER}")').replace("alert`1`", f'alert`{MARKER}`')
                q = dict(params); q[name] = [test]
                url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
                r = http.get(url)
                if not r: continue
                body = r.text

                # raw reflection
                if test in body:
                    findings.append({"param":name,"payload":test,"type":"raw"})
                    print(f"  [!] RAW: {name} | {test[:60]}")
                    logger.finding("xss_raw","medium",f"{name}={test[:80]}")
                # unescaped (marker present + no encoding)
                elif MARKER in body and "<" in test and "<" in body:
                    findings.append({"param":name,"payload":test,"type":"unescaped"})
                    print(f"  [!] UNESCAPED: {name} | {test[:60]}")
                    logger.finding("xss_unescaped","high",f"{name}={test[:80]}")
                # escaped markers only
                elif MARKER in body:
                    findings.append({"param":name,"payload":test,"type":"reflected_escaped"})
                    logger.finding("xss_reflect","low",f"{name} reflected escaped")

                if len(findings) > 30: break

        print(f"[xss] done: {len(findings)}")
        return {"findings": findings}
