"""session_hijack — chain: XSS + cookie theft + CSRF analysis"""
import re
from core.http import HttpClient
from core.probe import Probe


class SessionHijack:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        probe = Probe(session, logger)
        base = probe.baseline_probe(target)
        if not base:
            return {"findings": []}

        findings = []

        r = http.get(target)
        if r:
            insecure = []
            for c in r.cookies:
                raw = str(c._rest) if hasattr(c, "_rest") else ""
                if not c.secure:
                    insecure.append(f"{c.name}:no-secure")
                if "httponly" not in raw.lower():
                    insecure.append(f"{c.name}:no-httponly")
                if "samesite" not in raw.lower():
                    insecure.append(f"{c.name}:no-samesite")
            if insecure:
                print(f"  [!] insecure cookies: {insecure}")
                findings.append({"type": "insecure_cookies",
                                 "cookies": insecure, "severity": "medium"})
                logger.finding("session_hijack", "medium", str(insecure))

        xss_found = any("xss" in str(f.get("kind", "")).lower() for f in session.findings)
        if xss_found:
            print(f"  [!] XSS + weak cookies = session hijack path")
            findings.append({"type": "xss_session_hijack_path",
                             "severity": "critical"})
            logger.finding("session_hijack_chain", "critical",
                           "XSS + insecure cookies enables theft")

        if r:
            forms = re.findall(r'<form[^>]*method=["\']?post["\']?[^>]*>(.*?)</form>',
                               r.text, re.I | re.S)
            csrf_missing = 0
            for f in forms:
                if "csrf" not in f.lower() and "token" not in f.lower():
                    csrf_missing += 1
            if csrf_missing > 0:
                print(f"  [!] {csrf_missing} POST forms без CSRF")
                findings.append({"type": "csrf_missing", "count": csrf_missing,
                                 "severity": "medium"})
                logger.finding("csrf_missing", "medium", f"{csrf_missing} forms")

        print(f"[session_hijack] total: {len(findings)}")
        return {"findings": findings}
