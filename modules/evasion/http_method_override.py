"""http_method_override — test method override via headers (X-HTTP-Method-Override)"""
from core.http import HttpClient

OVERRIDES = [
    ("X-HTTP-Method", "PUT"),
    ("X-HTTP-Method-Override", "PUT"),
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-HTTP-Method-Override", "PATCH"),
    ("X-Method-Override", "PUT"),
]

class HttpMethodOverride:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        base = http.get(session.target)
        base_code = base.status_code if base else None
        print(f"[method_override] baseline GET -> {base_code}")

        for name, method in OVERRIDES:
            r = http.post(session.target, headers={name: method})
            if not r: continue
            if r.status_code != base_code:
                print(f"  [!] {name}: {method} -> {r.status_code}")
                logger.finding("method_override","medium",f"{name}: {method} -> {r.status_code}")
            else:
                print(f"     {name}: {method} -> {r.status_code}")

        # try POST with method override on common admin paths
        for path in ["/admin","/api/users","/users/1"]:
            r = http.post(session.target.rstrip("/") + path,
                          headers={"X-HTTP-Method-Override":"DELETE"})
            if r and r.status_code not in (404, 405, 501):
                logger.finding("method_override_path","medium",f"{path} accepts DELETE override")
        return {}
