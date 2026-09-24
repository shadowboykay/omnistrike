"""api_leak — scan JS bundles for API keys and secrets"""
import re
from core.http import HttpClient

JS_RE = re.compile(r'(?:src|href)=["\']([^"\']+\.js[^"\']*)', re.I)
PATTERNS = {
    "aws_key":     re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api":  re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "stripe":      re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "slack":       re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
    "github":      re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
    "jwt":         re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "generic_key": re.compile(r"(?:api[_-]?key|apikey|secret|token)['\"\s:=]{1,5}['\"]?([a-zA-Z0-9._\-]{20,})", re.I),
    "email":       re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
}

class ApiLeak:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        page = http.get(base)
        if not page: return {"leaks": []}
        js_paths = set(JS_RE.findall(page.text))
        leaks = []
        for js in list(js_paths)[:30]:
            u = js if js.startswith("http") else base + "/" + js.lstrip("/")
            r = http.get(u)
            if not r: continue
            for name, pat in PATTERNS.items():
                for m in pat.findall(r.text):
                    val = m if isinstance(m, str) else m[0]
                    if len(val) < 8: continue
                    leaks.append({"file": js, "type": name, "value": val[:80]})
                    print(f"  [!] {name}: {val[:60]}")
                    logger.finding("leak", "high" if name not in ("email",) else "low",
                                   f"{name} in {js}: {val[:60]}")
        print(f"[api_leak] done: {len(leaks)} leaks in {len(js_paths)} js")
        return {"leaks": leaks, "js_count": len(js_paths)}
