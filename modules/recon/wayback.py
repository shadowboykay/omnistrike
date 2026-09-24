"""wayback — pull historical URLs from web.archive.org CDX API"""
from core.http import HttpClient

class Wayback:
    def run(self, session, logger):
        d = session.target.replace("https://","").replace("http://","").split("/")[0]
        api = f"http://web.archive.org/cdx/search/cdx?url=*.{d}/*&output=json&collapse=urlkey&limit=5000&fl=original,statuscode,mimetype"
        http = HttpClient(session, logger)
        r = http.get(api)
        if not r or r.status_code != 200:
            print("[wayback] no data"); return {"urls": []}
        try:
            rows = r.json()[1:]
        except Exception:
            print("[wayback] bad json"); return {"urls": []}
        urls = []
        interesting = []
        KEY = (".env",".git","backup","dump",".sql","config","password",".bak",".old","admin","phpinfo",".zip",".tar")
        for row in rows:
            if len(row) < 3: continue
            u, code, mt = row[0], row[1], row[2]
            urls.append({"url": u, "code": code, "mime": mt})
            if any(k in u.lower() for k in KEY):
                interesting.append(u)
                logger.finding("wayback_interesting", "low", u)
        print(f"[wayback] {len(urls)} urls, {len(interesting)} interesting")
        for u in interesting[:30]: print(f"  [!] {u}")
        return {"domain": d, "total": len(urls), "interesting": interesting, "urls": urls[:500]}
