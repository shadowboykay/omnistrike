"""xslt_injection — XSLT processor injection (RCE/data disclosure)"""
from core.probe import Probe
from core.http import HttpClient
from core.payload_source import get_payloads

PAYLOADS = get_payloads("xslt")
MARKERS = ["libxslt", "sablotron", "Xalan", "MSXML", "phpinfo", "root:x:0:0",
           "XSLT", "vendor"]


class XsltInjection:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        probe = Probe(session, logger)
        probe.baseline_probe(session.target)
        print(f"[xslt] target: {session.target}")
        print(f"[xslt] {len(PAYLOADS)} payloads")

        findings = []
        for p in PAYLOADS:
            r = http.post(session.target, data=p,
                          headers={"Content-Type": "application/xml"})
            if not r:
                continue
            low = r.text.lower()
            hit = next((m for m in MARKERS if m.lower() in low), None)
            if not hit:
                continue
            sev = "critical" if hit in ("root:x:0:0", "phpinfo") else "high"
            print(f"  ✓ [{sev}] {hit}")
            findings.append({"payload": p[:60], "marker": hit,
                             "severity": sev, "verified": True})
            logger.finding("xslt_injection", sev, hit)

        print(f"[xslt] total: {len(findings)}")
        return {"findings": findings, "stats": probe.summary()}
