"""cookie — cookie security flag analysis"""
from core.http import HttpClient

class Cookie:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        r = http.get(session.target)
        if not r: return {}
        issues = []
        for c in r.cookies:
            raw = c._rest if hasattr(c, "_rest") else {}
            flags = {
                "secure": c.secure,
                "httponly": "HttpOnly" in str(raw) or c.has_nonstandard_attr("HttpOnly"),
                "samesite": raw.get("SameSite","") or ("SameSite" in str(raw)),
            }
            line = f"{c.name}: secure={c.secure} rest={raw}"
            print(f"  {line}")
            if not c.secure:
                issues.append(f"{c.name}:no_secure"); logger.finding("cookie", "medium", f"{c.name} missing Secure")
            if "httponly" not in str(raw).lower():
                issues.append(f"{c.name}:no_httponly"); logger.finding("cookie", "medium", f"{c.name} missing HttpOnly")
            if "samesite" not in str(raw).lower():
                issues.append(f"{c.name}:no_samesite"); logger.finding("cookie", "low", f"{c.name} missing SameSite")
        print(f"[cookie] {len(r.cookies)} cookies, {len(issues)} issues")
        return {"cookies": [c.name for c in r.cookies], "issues": issues}
