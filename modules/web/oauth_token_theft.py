"""oauth_token_theft v2 — OAuth token leakage analysis (не дублирует oauth_misconfig).

Фокус — на УТЕЧКАХ токена:
  1. Token endpoint без client auth (POST /oauth/token)
  2. JS storage leaks (localStorage/sessionStorage/postMessage)
  3. Debug endpoints (/oauth/tokens, /oauth/debug, /oauth/list)
  4. Cookie SameSite для OAuth callback
  5. Token в response body (без HTTPS / в HTML)
"""
import re
import json
import secrets
from urllib.parse import urlparse, urlencode
from core.http import HttpClient
from core.verify import confidence, is_signal


TOKEN_PATHS = [
    "/oauth/token", "/oauth2/token", "/api/oauth/token",
    "/auth/token", "/connect/token", "/token",
    "/oauth2/v2/token", "/oauth/access_token", "/api/token",
]

DEBUG_PATHS = [
    "/oauth/tokens", "/oauth/debug", "/oauth/list", "/oauth/admin",
    "/oauth/sessions", "/api/oauth/tokens", "/oauth/grants",
    "/oauth2/tokens", "/oauth/refresh-tokens",
]

CALLBACK_PATHS = [
    "/oauth/callback", "/oauth2/callback", "/auth/callback",
    "/callback", "/oauth/redirect",
]

# OAuth-related cookie names
OAUTH_COOKIES = ["oauth_state", "oauth_nonce", "oauth_token",
                 "csrf_state", "oauth_session", "id_token", "access_token"]


def _scan_js_for_leaks(text):
    """Ищет потенциальные утечки токенов в JS/HTML."""
    findings = []
    tl = text or ""

    # localStorage / sessionStorage
    patterns = [
        (r"localStorage\.setItem\s*\(\s*['\"](\w+)['\"]", "localStorage_set"),
        (r"sessionStorage\.setItem\s*\(\s*['\"](\w+)['\"]", "sessionStorage_set"),
        (r"document\.cookie\s*=\s*['\"]([^'\"]+)['\"]", "cookie_set_js"),
        (r"window\.postMessage\s*\([^,]+,\s*['\"]([^'\"]*)['\"]", "postMessage_target"),
    ]
    for pat, kind in patterns:
        for m in re.finditer(pat, tl, re.I):
            val = m.group(1)
            # postMessage target '*' — опасно
            if kind == "postMessage_target" and val == "*":
                findings.append({
                    "type": "postmessage_wildcard",
                    "severity": "medium",
                    "note": "window.postMessage called with '*' target origin",
                })
            # localStorage token
            if "token" in val.lower() or "auth" in val.lower() or "jwt" in val.lower():
                findings.append({
                    "type": f"{kind}_token",
                    "severity": "medium",
                    "key": val[:40],
                    "note": f"token stored in browser storage ({kind})",
                })
    return findings


class OauthTokenTheft:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        base = f"{u.scheme}://{u.netloc}"
        http = HttpClient(session, logger)

        print(f"[oauth_theft v2] target: {base}")

        findings = []

        # ============================================================
        # Phase 1: token endpoint без client auth
        # ============================================================
        print()
        print("[oauth_theft v2] Phase 1: token endpoint analysis")
        live_token_endpoints = []
        for path in TOKEN_PATHS:
            try:
                r = http.get(base + path, allow_redirects=False)
            except Exception:
                continue
            # POST без client auth
            try:
                r_post = http.post(base + path, data={
                    "grant_type": "authorization_code",
                    "code": "omni_test_code_xyz",
                    "redirect_uri": f"{base}/oauth/callback",
                    "client_id": "test_client",
                    # НЕТ client_secret — если сервер отвечает 200, уязвимость
                }, allow_redirects=False)
            except Exception:
                continue

            if r_post and r_post.status_code == 200:
                body_low = (r_post.text or "").lower()
                if "access_token" in body_low or "error" not in body_low:
                    if r_post.status_code == 200 and "access_token" in body_low:
                        conf = confidence(0.9, 1.0)
                        if is_signal(conf, floor=0.55, module="oauth_theft"):
                            findings.append({
                                "type": "token_endpoint_no_client_auth",
                                "severity": "critical",
                                "path": path,
                                "response": (r_post.text or "")[:200],
                                "confidence": conf,
                            })
                            print(f"  ✓ token endpoint без client auth: {path}")
                            logger.finding("oauth_token_no_auth", "critical", path)
                            break
            # 401/400 — endpoint живой, но требует auth
            if r_post and r_post.status_code in (400, 401, 403):
                live_token_endpoints.append(path)

        if live_token_endpoints:
            print(f"  live token endpoints (require auth): {live_token_endpoints}")

        # ============================================================
        # Phase 2: debug endpoints
        # ============================================================
        print()
        print("[oauth_theft v2] Phase 2: debug/leak endpoints")
        for path in DEBUG_PATHS:
            try:
                r = http.get(base + path, allow_redirects=False)
            except Exception:
                continue
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            # JSON с tokens?
            try:
                data = r.json()
                if isinstance(data, (list, dict)):
                    # ищем токен-подобные значения
                    if any(k in str(data).lower() for k in ("access_token", "refresh_token", "id_token", "bearer")):
                        conf = confidence(0.9, 1.0)
                        if is_signal(conf, floor=0.55, module="oauth_theft"):
                            findings.append({
                                "type": "oauth_debug_endpoint",
                                "severity": "critical",
                                "path": path,
                                "sample": str(data)[:200],
                                "confidence": conf,
                            })
                            print(f"  ✓ debug endpoint leaks tokens: {path}")
                            logger.finding("oauth_debug", "critical", path)
                            break
            except Exception:
                pass

        # ============================================================
        # Phase 3: JS storage leaks
        # ============================================================
        print()
        print("[oauth_theft v2] Phase 3: JS storage leaks")
        # главная + login + oauth paths
        scan_pages = [target]
        for p in ["/login", "/oauth/callback", "/oauth/authorize"]:
            scan_pages.append(base + p)

        js_findings = []
        for url in scan_pages:
            try:
                r = http.get(url, allow_redirects=True)
            except Exception:
                continue
            if not r:
                continue
            leaks = _scan_js_for_leaks(r.text or "")
            js_findings.extend(leaks)

        # дедупликация
        seen_keys = set()
        for lf in js_findings:
            key = (lf["type"], lf.get("key", ""))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            conf = confidence(0.65, 1.0)
            if is_signal(conf, floor=0.55, module="oauth_theft"):
                lf["confidence"] = conf
                findings.append(lf)
                print(f"  ✓ JS leak: {lf['type']} ({lf.get('key', '')[:30]})")
                logger.finding("oauth_js_leak", lf["severity"], lf["type"])

        # ============================================================
        # Phase 4: cookie SameSite для OAuth callback
        # ============================================================
        print()
        print("[oauth_theft v2] Phase 4: OAuth callback cookie flags")
        for path in CALLBACK_PATHS:
            try:
                r = http.get(base + path, allow_redirects=False)
            except Exception:
                continue
            if not r:
                continue
            # смотрим Set-Cookie headers
            for k, v in r.headers.items():
                if k.lower() != "set-cookie":
                    continue
                vl = str(v).lower()
                if any(oc in vl for oc in OAUTH_COOKIES):
                    # если нет SameSite
                    if "samesite" not in vl:
                        conf = confidence(0.75, 1.0)
                        if is_signal(conf, floor=0.55, module="oauth_theft"):
                            findings.append({
                                "type": "oauth_cookie_no_samesite",
                                "severity": "medium",
                                "path": path,
                                "cookie": str(v)[:100],
                                "confidence": conf,
                            })
                            print(f"  ✓ OAuth cookie без SameSite: {path}")
                            logger.finding("oauth_cookie_samesite", "medium", path)

        # ============================================================
        # Итог
        # ============================================================
        print()
        print(f"[oauth_theft v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "token_endpoints": live_token_endpoints,
        }
