"""dorks — Google dork URL generator + optional SERP check via DuckDuckGo html"""
import urllib.parse
from core.http import HttpClient

DORKS = [
    'site:{d} inurl:admin', 'site:{d} inurl:login', 'site:{d} inurl:api',
    'site:{d} ext:sql', 'site:{d} ext:env', 'site:{d} ext:log', 'site:{d} ext:bak',
    'site:{d} ext:old', 'site:{d} ext:zip', 'site:{d} ext:tar.gz',
    'site:{d} intitle:"index of"', 'site:{d} inurl:config', 'site:{d} inurl:backup',
    'site:{d} inurl:.git', 'site:{d} inurl:.svn', 'site:{d} inurl:phpinfo',
    'site:{d} "password"', 'site:{d} "api_key"', 'site:{d} "secret"',
    'site:{d} inurl:wp-admin', 'site:{d} inurl:wp-content', 'site:{d} inurl:xmlrpc',
    'site:{d} inurl:phpmyadmin', 'site:{d} inurl:server-status',
]

class Dorks:
    def run(self, session, logger):
        d = session.target.replace("https://","").replace("http://","").split("/")[0]
        print(f"[dorks] {d} — {len(DORKS)} dorks")
        out = []
        for t in DORKS:
            q = t.format(d=d)
            url = "https://duckduckgo.com/html/?q=" + urllib.parse.quote(q)
            out.append({"dork": q, "url": url})
            print(f"  {q}")
        logger.info("dorks_done", count=len(out))
        return {"domain": d, "dorks": out}
