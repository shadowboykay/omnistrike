"""google_cache — fetch Google cache + check search availability"""
from urllib.parse import quote
from core.http import HttpClient

class GoogleCache:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        print(f"[google_cache] {target}")
        url = f"https://webcache.googleusercontent.com/search?q=cache:{quote(target)}"
        r = http.get(url)
        if not r: return {}
        if r.status_code == 200 and "cache" not in r.url.lower():
            print(f"  [+] cache available")
            logger.finding("google_cache","info",target)
        else:
            print(f"  no cache ({r.status_code})")
        # also archive.org
        r2 = http.get(f"http://archive.org/wayback/available?url={quote(target)}")
        if r2 and r2.status_code == 200:
            data = r2.json()
            snapshot = data.get("archived_snapshots",{}).get("closest",{})
            if snapshot:
                print(f"  [+] wayback: {snapshot.get('url','')}")
                logger.finding("wayback_snapshot","info",snapshot.get("url",""))
        return {}
