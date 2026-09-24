"""deserialization_advanced — Java/PHP/Python/.NET deserialization payloads"""
import base64
from core.http import HttpClient
from core.payload_source import get_payloads
from core.probe import Probe

# Java serialized magic (YSOSERIAL, CommonsCollections)
JAVA_PAYLOADS = get_payloads("deser", limit=3)

# PHP serialized
PHP_PAYLOADS = get_payloads("deser", limit=3)

# Python pickle
PY_PAYLOADS = get_payloads("deser", limit=3)

# .NET ViewState / BinaryFormatter
NET_PAYLOADS = get_payloads("deser", limit=3)

MARKERS = [
    "java.io", "ObjectInputStream", "ClassNotFoundException",
    "unserialize()", "PHP Fatal", "__PHP_Incomplete_Class",
    "pickle", "UnpicklingError", "invalid load key",
    "BinaryFormatter", "ViewState", "SerializationException",
    "ClassCastException", "javax.servlet",
]

DETECT_PATHS = [
    "/api/deserialize", "/api/v1/deserialize", "/rpc", "/invoke",
    "/api/import", "/api/parse", "/api/load", "/api/decode", "/upload",
    "/api/session", "/session", "/auth/session",
]

class DeserializationAdvanced:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        findings = []

        # 1. cookie check
        r = http.get(session.target)
        if r:
            for c in r.cookies:
                v = c.value
                if v.startswith("rO0AB"):
                    print(f"  [!] Java serialized cookie: {c.name}")
                    findings.append({"location": "cookie", "name": c.name, "lang": "java",
                                     "severity": "critical"})
                    logger.finding("deser_java_cookie", "critical", c.name)
                elif v.startswith("a:") and "O:" in v:
                    print(f"  [!] PHP serialized cookie: {c.name}")
                    findings.append({"location": "cookie", "name": c.name, "lang": "php",
                                     "severity": "critical"})
                    logger.finding("deser_php_cookie", "critical", c.name)

        # 2. probe known endpoints with each payload family
        for path in DETECT_PATHS:
            r0 = http.get(base + path)
            if not r0 or r0.status_code == 404: continue
            print(f"[deser] found: {path} ({r0.status_code})")

            for lang, pls in [("java", JAVA_PAYLOADS), ("php", PHP_PAYLOADS),
                              ("python", PY_PAYLOADS), ("net", NET_PAYLOADS)]:
                for p in pls[:2]:
                    r = http.post(base + path, data=p,
                                  headers={"Content-Type": "application/octet-stream"})
                    if not r: continue
                    low = r.text.lower()
                    hit = next((m for m in MARKERS if m.lower() in low), None)
                    if hit:
                        print(f"  [!] {lang} deser at {path}: {hit}")
                        findings.append({"path": path, "lang": lang, "marker": hit,
                                         "severity": "critical", "verified": True})
                        logger.finding("deserialization", "critical",
                                       f"{lang} {path} -> {hit}")
                        break

        print(f"[deser_advanced] total: {len(findings)}")
        return {"findings": findings}
