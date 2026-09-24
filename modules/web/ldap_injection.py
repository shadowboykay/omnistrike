"""ldap_injection — LDAP filter injection probe"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.probe import Probe
from core.payload_source import get_payloads

PAYLOADS = get_payloads("ldap", limit=40)
MARKERS = [
    "javax.naming.NameNotFoundException",
    "javax.naming.directory.InvalidSearchFilterException",
    "com.sun.jndi.ldap",
    "LDAPException:",
    "invalid DN syntax",
    "ldap_bind: ",
    "invalidCredentials (49)",
    "no such object (32)",
    "objectClass: ",
    "cn=admin,dc=",
    "userPassword",
    "LDAPv3",
    "search: 2",
    "result: 32",
]

class LdapInjection:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"user": ["admin"]}
        probe = Probe(session, logger)
        base = probe.baseline_probe(target)
        if not base:
            print("[ldap] no baseline"); return {"findings": []}
        print(f"[ldap] baseline: {base['code']} {base['len']}b")
        findings = []
        for name in params:
            for p in PAYLOADS:
                url_fn = lambda pl, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()}, name: pl}, doseq=True)))
                r = probe.inject(url_fn, p, detect_markers=MARKERS)
                if not r["hit"]: continue
                verified = probe.verify(url_fn, p, detect_markers=MARKERS, times=2)
                if not verified: continue
                sev = probe.escalate_severity("high", r,
                       r.get("response").text if r.get("response") is not None else "")
                print(f"  ✓ [{sev}] LDAP: {name}={p[:50]}")
                findings.append({"param": name, "payload": p, "severity": sev, "verified": True})
                logger.finding("ldap_injection", sev, f"{name}={p[:50]}")
        print(f"[ldap] total: {len(findings)}")
        return {"findings": findings, "stats": probe.summary()}
