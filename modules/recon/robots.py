"""robots — parse robots.txt for disallowed paths + sitemaps"""
import re
from core.http import HttpClient

DISALLOW_RE = re.compile(r"^Disallow:\s*(\S+)", re.I | re.M)

class Robots:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        r = http.get(base + "/robots.txt")
        if not r or r.status_code != 200:
            print("[robots] not found"); return {"disallow": [], "raw": ""}
        disallow = [d for d in DISALLOW_RE.findall(r.text) if d and d != "/"]
        print(f"[robots] {len(disallow)} disallow entries")
        for d in disallow:
            print(f"  {d}")
            if any(k in d.lower() for k in ("admin","backup","config","private","api","db","secret")):
                logger.finding("robots_interesting", "low", d)
        return {"disallow": disallow, "raw": r.text}
