"""xxe — XML external entity probe (in-band file read)"""
from core.http import HttpClient
from core.payload_source import get_payloads

PAYLOADS = get_payloads("xml", limit=50)
MARKERS = ["root:x:0:0","[fonts]","[extensions]","for 16-bit"]

class Xxe:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        findings = []
        for p in PAYLOADS:
            r = http.post(session.target, data=p,
                          headers={"Content-Type":"application/xml"})
            if not r: continue
            for m in MARKERS:
                if m in r.text:
                    findings.append({"payload":p[:60],"marker":m})
                    print(f"  [!] XXE in-band: {m}")
                    logger.finding("xxe", "critical", f"marker={m}")
                    break
        print(f"[xxe] done: {len(findings)}")
        return {"findings": findings}
