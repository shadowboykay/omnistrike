"""sitemap — fetch sitemap.xml + robots.txt and extract URLs"""
import re
from core.http import HttpClient

LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
SITEMAP_RE = re.compile(r"^Sitemap:\s*(\S+)", re.I | re.M)

class Sitemap:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        urls = []
        for p in ["/sitemap.xml","/sitemap_index.xml","/sitemap-index.xml"]:
            r = http.get(base + p)
            if r and r.status_code == 200:
                found = LOC_RE.findall(r.text)
                print(f"  [+] {p} -> {len(found)} urls")
                urls.extend(found)
                for sm in [u for u in found if u.endswith(".xml")][:10]:
                    sr = http.get(sm)
                    if sr: urls.extend(LOC_RE.findall(sr.text))
        rb = http.get(base + "/robots.txt")
        if rb and rb.status_code == 200:
            sms = SITEMAP_RE.findall(rb.text)
            print(f"  [+] robots.txt -> {len(sms)} sitemaps")
            for sm in sms:
                sr = http.get(sm)
                if sr: urls.extend(LOC_RE.findall(sr.text))
        urls = sorted(set(urls))
        print(f"[sitemap] {len(urls)} unique urls")
        logger.info("sitemap_done", count=len(urls))
        return {"urls": urls[:1000]}
