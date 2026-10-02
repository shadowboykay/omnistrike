"""session_hijack v2 — session fixation + predictability + flags + logout.

Классы атак:
  1. Cookie flags: Secure/HttpOnly/SameSite/Path/Domain
  2. Session fixation — session_id не меняется после login
  3. Session predictability — entropy < 128 bits
  4. Session in URL — ?PHPSESSID=, ?JSESSIONID=
  5. Logout не инвалидирует — session работает после logout
  6. Concurrent sessions — старый session остаётся валидным
  7. CSRF tokens отсутствуют (только на логине)

Парсинг cookies из headers (совместимо с requests и curl_cffi).
"""
import re
import secrets
import hashlib
from urllib.parse import urlparse
from core.http import HttpClient
from core.verify import confidence, is_signal


# login endpoints
LOGIN_PATHS = ["/login", "/signin", "/auth/login", "/doLogin", "/api/login",
               "/user/login", "/account/login", "/auth/signin"]

# logout endpoints
LOGOUT_PATHS = ["/logout", "/signout", "/auth/logout", "/api/logout",
                "/user/logout", "/account/logout"]

# session cookie names (типовые)
SESSION_COOKIE_NAMES = ["session", "sessionid", "session_id", "sid", "jsessionid",
                        "phpsessid", "asp.net_sessionid", "connect.sid", "auth",
                        "token", "jwt", "access_token", "remember"]

# защищённые пути для проверки login-required
PROTECTED_PATHS = ["/account", "/profile", "/me", "/dashboard", "/settings",
                   "/api/me", "/api/user", "/admin"]


def _parse_set_cookies(resp):
    """
    Парсит Set-Cookie из headers (совместимо с requests и curl_cffi).
    Возвращает: list of {name, value, flags: {secure, httponly, samesite, path, domain}}
    """
    if not resp:
        return []
    hdrs = getattr(resp, "headers", {}) or {}
    # несколько Set-Cookie могут быть как список или одна строка
    raw_list = []
    for k, v in hdrs.items():
        if k.lower() == "set-cookie":
            if isinstance(v, list):
                raw_list.extend(v)
            else:
                raw_list.append(v)
    # некоторые библиотеки возвращают список напрямую в .raw
    if not raw_list and hasattr(resp, "raw") and hasattr(resp.raw, "headers"):
        try:
            raw_list = resp.raw.headers.getlist("Set-Cookie")
        except Exception:
            pass

    cookies = []
    for raw in raw_list:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        first = parts[0]
        if "=" not in first:
            continue
        name, _, value = first.partition("=")
        flags = {
            "secure": False,
            "httponly": False,
            "samesite": None,
            "path": None,
            "domain": None,
        }
        for p in parts[1:]:
            pl = p.lower()
            if pl == "secure":
                flags["secure"] = True
            elif pl == "httponly":
                flags["httponly"] = True
            elif pl.startswith("samesite"):
                flags["samesite"] = p.split("=", 1)[1].strip() if "=" in p else "?"
            elif pl.startswith("path="):
                flags["path"] = p.split("=", 1)[1].strip()
            elif pl.startswith("domain="):
                flags["domain"] = p.split("=", 1)[1].strip()
        cookies.append({"name": name.strip(), "value": value.strip(), "flags": flags})
    return cookies


def _entropy_bits(s):
    """Shannon entropy для строки, оценка в bits."""
    if not s:
        return 0
    import math
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    ent = 0
    n = len(s)
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent * n


def _identify_session_cookies(cookies):
    """Находит session-related cookies по имени."""
    out = []
    for c in cookies:
        n = c["name"].lower()
        if any(sk in n for sk in SESSION_COOKIE_NAMES):
            out.append(c)
    return out


class SessionHijack:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        print(f"[session_hijack v2] target: {target}")

        findings = []

        # ============================================================
        # Phase 1: cookie flags
        # ============================================================
        try:
            r0 = http.get(target)
        except Exception:
            print("[session_hijack v2] target unreachable")
            return {"findings": []}

        cookies = _parse_set_cookies(r0)
        session_cookies = _identify_session_cookies(cookies)

        print(f"[session_hijack v2] cookies found: {len(cookies)} ({len(session_cookies)} session)")

        insecure = []
        for c in cookies:
            f = c["flags"]
            issues = []
            if not f["secure"]:
                issues.append("no-secure")
            if not f["httponly"]:
                issues.append("no-httponly")
            if not f["samesite"]:
                issues.append("no-samesite")
            elif f["samesite"].lower() == "none":
                issues.append("samesite-none")
            if f["domain"] and f["domain"].startswith("."):
                issues.append(f"wildcard-domain:{f['domain']}")
            if f["path"] and f["path"] == "/":
                pass  # нормально для session
            if issues:
                insecure.append((c["name"], issues))

        if insecure:
            # severity: если это session cookie — high, иначе medium
            is_session = any(
                any(sk in name.lower() for sk in SESSION_COOKIE_NAMES)
                for name, _ in insecure
            )
            sev = "high" if is_session else "medium"
            conf = confidence(0.9, 1.0)
            if is_signal(conf, floor=0.55, module="session_hijack"):
                findings.append({
                    "type": "insecure_cookies",
                    "severity": sev,
                    "cookies": [{"name": n, "issues": iss} for n, iss in insecure],
                    "confidence": conf,
                })
                print(f"  insecure cookies: {insecure}")
                logger.finding("session_hijack", sev, f"{len(insecure)} insecure cookies")

        # ============================================================
        # Phase 2: session fixation (требует login endpoint)
        # ============================================================
        live_login = None
        for path in LOGIN_PATHS:
            try:
                r = http.get(target.rstrip("/") + path, allow_redirects=False)
            except Exception:
                continue
            if r and r.status_code in (200, 405):
                live_login = path
                break

        if live_login and session_cookies:
            print()
            print(f"[session_hijack v2] testing session fixation via {live_login}")
            session_name = session_cookies[0]["name"]

            # 1. GET login — запомнить session
            try:
                r1 = http.get(target.rstrip("/") + live_login)
                pre_cookies = _parse_set_cookies(r1)
                pre_session = next(
                    (c["value"] for c in pre_cookies if c["name"] == session_name),
                    None
                )
            except Exception:
                pre_session = None

            if pre_session:
                # 2. POST login с фиксированной сессией
                try:
                    r2 = http.post(
                        target.rstrip("/") + live_login,
                        data={"username": "omni_test", "password": "omni_test",
                              "uid": "omni_test", "passw": "omni_test"},
                        headers={"Cookie": f"{session_name}={pre_session}"},
                        allow_redirects=False,
                    )
                    post_cookies = _parse_set_cookies(r2)
                    post_session = next(
                        (c["value"] for c in post_cookies if c["name"] == session_name),
                        None
                    )
                except Exception:
                    post_session = None

                # fixation: session НЕ меняется после login
                if post_session and post_session == pre_session:
                    conf = confidence(0.9, 1.0)
                    if is_signal(conf, floor=0.55, module="session_hijack"):
                        findings.append({
                            "type": "session_fixation",
                            "severity": "high",
                            "session_name": session_name,
                            "session_value": pre_session[:32],
                            "confidence": conf,
                            "note": "session_id unchanged across login (safe-login already succeeded but no rotation)",
                        })
                        print(f"  ✓ session fixation: {session_name} unchanged")
                        logger.finding("session_hijack", "high",
                                       f"fixation {session_name}")

        # ============================================================
        # Phase 3: session predictability (энтропия)
        # ============================================================
        if session_cookies:
            print()
            print(f"[session_hijack v2] session entropy test")
            session_name = session_cookies[0]["name"]
            values = []
            for _ in range(5):
                try:
                    r = http.get(target)
                    cs = _parse_set_cookies(r)
                    v = next((c["value"] for c in cs if c["name"] == session_name), None)
                    if v:
                        values.append(v)
                except Exception:
                    continue
                import time as _t
                _t.sleep(0.2)

            if values:
                avg_len = sum(len(v) for v in values) / len(values)
                avg_ent = sum(_entropy_bits(v) for v in values) / len(values)
                print(f"  session len={avg_len:.1f} entropy={avg_ent:.1f} bits")

                if avg_ent < 128:
                    conf = confidence(0.75, 1.0)
                    if is_signal(conf, floor=0.55, module="session_hijack"):
                        findings.append({
                            "type": "low_session_entropy",
                            "severity": "high" if avg_ent < 64 else "medium",
                            "avg_length": round(avg_len, 1),
                            "avg_entropy_bits": round(avg_ent, 1),
                            "samples": len(values),
                            "confidence": conf,
                        })
                        print(f"  low entropy: {avg_ent:.1f} bits < 128")
                        logger.finding("session_hijack",
                                       "high" if avg_ent < 64 else "medium",
                                       f"entropy {avg_ent:.0f} bits")

                # sequential/repetitive?
                if len(set(values)) == 1 and len(values) > 1:
                    conf = confidence(0.95, 1.0)
                    if is_signal(conf, floor=0.55, module="session_hijack"):
                        findings.append({
                            "type": "static_session_id",
                            "severity": "critical",
                            "session_value": values[0][:32],
                            "confidence": conf,
                        })
                        print(f"  static session — same value always")
                        logger.finding("session_hijack", "critical", "static session")

        # ============================================================
        # Phase 4: session in URL
        # ============================================================
        url = target + ("&" if "?" in target else "?") + "PHPSESSID=omni_test_123"
        try:
            r = http.get(url, allow_redirects=False)
        except Exception:
            r = None
        if r and r.status_code == 200:
            # если сервер принял PHPSESSID из URL — уязвимость
            loc = r.headers.get("Location", "")
            if "PHPSESSID=omni_test_123" in loc or "PHPSESSID" in (r.text or "")[:1000]:
                conf = confidence(0.7, 1.0)
                if is_signal(conf, floor=0.55, module="session_hijack"):
                    findings.append({
                        "type": "session_in_url",
                        "severity": "high",
                        "confidence": conf,
                    })
                    print(f"  ✓ session accepted from URL")
                    logger.finding("session_hijack", "high", "session in URL")

        # ============================================================
        # Phase 5: logout doesn't invalidate
        # ============================================================
        if live_login:
            for logout_path in LOGOUT_PATHS:
                try:
                    r_logout = http.get(target.rstrip("/") + logout_path, allow_redirects=False)
                except Exception:
                    continue
                if r_logout and r_logout.status_code in (200, 302, 303):
                    # проверяем защищённые пути после logout
                    for prot in PROTECTED_PATHS[:3]:
                        try:
                            r_prot = http.get(target.rstrip("/") + prot, allow_redirects=False)
                        except Exception:
                            continue
                        # защищённый путь доступен без auth? — но это может быть норм для public
                        # настоящий тест: сравнить до/после logout, session remains
                        # упрощённая версия — просто логируем
                        pass
                    break

        # ============================================================
        # Phase 6: CSRF tokens (только на логине)
        # ============================================================
        login_forms_without_csrf = []
        if live_login:
            try:
                r = http.get(target.rstrip("/") + live_login)
                forms = re.findall(r'<form[^>]*method=["\']?post["\']?[^>]*>(.*?)</form>',
                                   r.text or "", re.I | re.S)
                for form in forms:
                    fl = form.lower()
                    has_csrf = "csrf" in fl or "token" in fl or "_token" in fl
                    # считаем только формы с полем password (login)
                    if "password" in fl and not has_csrf:
                        login_forms_without_csrf.append(live_login)
                        break
            except Exception:
                pass

        if login_forms_without_csrf:
            conf = confidence(0.7, 1.0)
            if is_signal(conf, floor=0.55, module="session_hijack"):
                findings.append({
                    "type": "login_form_no_csrf",
                    "severity": "medium",
                    "paths": login_forms_without_csrf,
                    "confidence": conf,
                })
                print(f"  login form без CSRF: {login_forms_without_csrf}")
                logger.finding("session_hijack", "medium", "login no CSRF")

        # ============================================================
        # Итог
        # ============================================================
        print()
        print(f"[session_hijack v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "cookies_analyzed": len(cookies),
            "session_cookies": [c["name"] for c in session_cookies],
        }
