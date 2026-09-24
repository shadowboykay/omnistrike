"""cookie_rotate — rotate session cookies across requests (multi-account scan)"""
from core.http import HttpClient

class CookieRotate:
    def run(self, session, logger):
        cookies = []
        for x in session.extra:
            if x.startswith("cookie="):
                cookies.append(x.split("=",1)[1])
        if not cookies:
            print("[cookie_rotate] provide cookies via --extra cookie='name=value'")
            return {}

        print(f"[cookie_rotate] {len(cookies)} cookies")
        results = []
        for c in cookies:
            name, _, val = c.partition("=")
            headers = {"Cookie": f"{name}={val}"}
            r = HttpClient(session, logger).get(session.target, headers=headers)
            code = r.status_code if r else None
            results.append({"cookie":c[:20],"code":code})
            print(f"  {c[:30]} -> {code}")
        return {"results": results}
