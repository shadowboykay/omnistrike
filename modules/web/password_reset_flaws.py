"""password_reset_flaws — password reset flow: token leak, host poison, weak token"""
import re
from urllib.parse import urlparse
from core.http import HttpClient
from core.probe import Probe

RESET_PATHS = ["/forgot", "/forgot-password", "/password/reset", "/password/forgot",
               "/reset", "/reset-password", "/account/recover", "/users/password/new",
               "/auth/forgot", "/api/password/reset", "/api/auth/forgot"]

class PasswordResetFlaws:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        findings = []

        for path in RESET_PATHS:
            r = http.get(base + path)
            if not r or r.status_code not in (200, 405): continue
            print(f"[reset] {path} ({r.status_code})")

            # try sending reset
            r2 = http.post(base + path, data={"email": "test@example.com"},
                           allow_redirects=False)
            if not r2: continue

            # token in URL
            loc = r2.headers.get("Location", "")
            m = re.search(r"[?&](token|reset_token|code|key)=([A-Za-z0-9_\-]{6,})", loc)
            if m:
                print(f"  [!] token in URL: {m.group(1)}={m.group(2)[:20]}")
                findings.append({"path": path, "type": "token_in_url",
                                 "token": m.group(2)[:20], "severity": "high"})
                logger.finding("reset_token_url", "high", path)

            # short/predictable token in body
            m2 = re.search(r"(token|code|reset)[\"'\s:=]+([A-Za-z0-9]{4,10})[\"'<]", r2.text, re.I)
            if m2 and len(m2.group(2)) < 12:
                print(f"  [!] short token: {m2.group(2)}")
                findings.append({"path": path, "type": "short_token",
                                 "token": m2.group(2), "severity": "high"})
                logger.finding("reset_short_token", "high", m2.group(2))

            # no email confirmation (200 but same response for any email)
            r3 = http.post(base + path, data={"email": "nonexistent_xyz@example.com"})
            if r3 and r3.status_code == 200 and r2.status_code == 200:
                if len(r3.content) == len(r2.content):
                    print(f"  [!] same response for any email — user enum possible")
                    findings.append({"path": path, "type": "user_enum",
                                     "severity": "medium"})

        # Host header poison on reset
        for path in RESET_PATHS[:3]:
            r = http.post(base + path, data={"email": "test@example.com"},
                          headers={"Host": "evil.attacker.example",
                                   "X-Forwarded-Host": "evil.attacker.example"},
                          allow_redirects=False)
            if r and "evil" in r.text:
                print(f"  [!] host header reflected in reset response")
                findings.append({"path": path, "type": "host_poison",
                                 "severity": "critical"})
                logger.finding("reset_host_poison", "critical", path)

        print(f"[password_reset] total: {len(findings)}")
        return {"findings": findings}
