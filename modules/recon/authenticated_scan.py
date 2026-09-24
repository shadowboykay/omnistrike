"""authenticated_scan — scan with credentials (5-10x more findings than anonymous)"""
from core.http import HttpClient
from core.payload_source import get_payloads, detect_waf
import json
import re


class AuthenticatedScan:
    """
    Сканирует target с credentials. Даёт доступ к:
      - защищённым страницам (/admin, /api/users)
      - расширенным API endpoints
      - внутренним функциям
    """

    def run(self, session, logger):
        # credentials from --extra creds=user:pass
        creds = None
        login_path = None
        login_data = None
        for x in session.extra:
            if x.startswith("creds="):
                u, _, p = x[6:].partition(":")
                creds = (u, p)
            elif x.startswith("login="):
                login_path = x.split("=", 1)[1]
            elif x.startswith("login_data="):
                login_data = x.split("=", 1)[1]

        if not creds:
            print("[auth_scan] укажи --extra 'creds=user:pass'")
            print("  опц: --extra 'login=/login' --extra 'login_data=uid=user&passw=pass'")
            return {"scanned": False}

        user, pw = creds
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)

        print(f"[auth_scan] target: {base}")
        print(f"[auth_scan] creds: {user}:{'*' * len(pw)}")
        print()

        # 1. login
        print("=" * 60)
        print("1. LOGIN")
        print("=" * 60)

        if login_path and login_data:
            data = login_data.replace("USER", user).replace("PASS", pw)
            r = http.post(base + login_path, data=data)
            print(f"  {login_path} -> {r.status_code if r else 'no response'}")
        else:
            # try common login paths
            for path in ["/login", "/doLogin", "/auth/login", "/api/login", "/signin"]:
                for fields in [(user, pw), (user, pw)]:
                    r = http.post(base + path, data={"username": user, "password": pw})
                    if not r:
                        r = http.post(base + path, data={"uid": user, "passw": pw})
                    if r and r.status_code in (200, 302):
                        print(f"  {path} -> {r.status_code}")
                        break

        # 2. crawлю защищённые страницы
        print()
        print("=" * 60)
        print("2. АУТЕНТИФИЦИРОВАННЫЙ CRAWL")
        print("=" * 60)

        protected_paths = [
            "/admin", "/admin/", "/admin/users", "/admin/config",
            "/api/users", "/api/me", "/api/profile",
            "/dashboard", "/settings", "/profile",
            "/internal", "/manage", "/console",
        ]

        accessible = []
        for path in protected_paths:
            r = http.get(base + path)
            if r and r.status_code == 200:
                accessible.append(path)
                print(f"  + {path} ({len(r.content)}b)")

        print(f"\n  accessible: {len(accessible)} paths")

        # 3. API fuzzing с cookies
        print()
        print("=" * 60)
        print("3. API С АВТОРИЗАЦИЕЙ")
        print("=" * 60)

        api_paths = [
            "/api/users", "/api/me", "/api/v1/admin",
            "/api/config", "/api/logs", "/api/debug",
            "/api/settings", "/api/tokens", "/api/keys",
        ]

        api_data = []
        for path in api_paths:
            r = http.get(base + path)
            if r and r.status_code == 200 and "json" in r.headers.get("Content-Type", ""):
                try:
                    data = r.json()
                    api_data.append({"path": path, "data": data})
                    print(f"  + {path}: {str(data)[:80]}")
                    logger.finding("auth_api_exposed", "high", path)
                except Exception:
                    pass

        # 4. поиск секретов в авторизованном контенте
        print()
        print("=" * 60)
        print("4. СЕКРЕТЫ В ЗАЩИЩЁННОМ КОНТЕНТЕ")
        print("=" * 60)

        secret_patterns = {
            "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
            "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
            "api_key": re.compile(r"(?:api[_-]?key|apikey)['\"\s:=]+([A-Za-z0-9_\-]{20,})", re.I),
            "password": re.compile(r"(?:password|passwd|pwd)['\"\s:=]+([^\s\"']{6,})", re.I),
        }

        secrets = []
        for path in accessible[:10]:
            r = http.get(base + path)
            if not r:
                continue
            for name, pat in secret_patterns.items():
                for m in pat.findall(r.text):
                    val = m if isinstance(m, str) else m[0]
                    print(f"  ! {name} в {path}: {val[:40]}")
                    secrets.append({"path": path, "type": name, "value": val[:60]})
                    logger.finding("auth_secret", "critical", f"{name} in {path}")

        print()
        print(f"[auth_scan] accessible: {len(accessible)}, api: {len(api_data)}, secrets: {len(secrets)}")
        return {
            "user": user,
            "accessible": accessible,
            "api_endpoints": [d["path"] for d in api_data],
            "secrets": secrets,
        }
