"""cache_deception — Web Cache Deception (RCD) probe"""
from core.http import HttpClient
from core.probe import Probe

# extension suffixes that trick CDN into caching
SUFFIXES = [
    ".css", ".js", ".jpg", ".png", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    "/", "//", "/%20", "/;.css", "/.css", "%0a.css", "%00.css",
    "/.jpg", "?x=.css", "?/.css", "/index.css", "/app.js",
]

# endpoints that return sensitive data when authenticated
PRIVATE_PATHS = [
    "/profile", "/account", "/api/me", "/api/user", "/dashboard",
    "/settings", "/admin", "/api/admin", "/api/token", "/me",
    "/api/v1/user", "/user/profile", "/account/settings",
]


class CacheDeception:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        findings = []

        for path in PRIVATE_PATHS:
            r0 = http.get(base + path)
            if not r0 or r0.status_code not in (200, 401, 403): continue
            print(f"[cache_deception] {path} -> {r0.status_code}")

            for suf in SUFFIXES[:8]:
                test_url = base + path + suf
                r = http.get(test_url, allow_redirects=False)
                if not r: continue

                # if same content as original but cache headers appear
                cache_status = (r.headers.get("X-Cache") or
                                r.headers.get("CF-Cache-Status") or
                                r.headers.get("X-Cache-Status") or "")
                age = r.headers.get("Age", "")

                if r.status_code == 200 and (cache_status or age):
                    if "hit" in str(cache_status).lower() or age:
                        print(f"  [!] cached: {test_url} (X-Cache={cache_status}, Age={age})")
                        findings.append({"path": path, "suffix": suf, "url": test_url,
                                         "cache_status": str(cache_status), "age": age,
                                         "severity": "high"})
                        logger.finding("cache_deception", "high", test_url)

                # extension reflected in content
                if r.status_code == 200 and len(r.content) > 500:
                    if abs(len(r.content) - len(r0.content)) < 50:
                        print(f"  [+] same content, ext added: {suf}")
                        findings.append({"path": path, "suffix": suf,
                                         "type": "content_match", "severity": "medium"})

        print(f"[cache_deception] total: {len(findings)}")
        return {"findings": findings}
