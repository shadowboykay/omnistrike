"""email_harvest — collect emails from target site + common pages"""
import re
from core.http import HttpClient
from concurrent.futures import ThreadPoolExecutor, as_completed

PAGES = ["/","/contact","/about","/team","/support","/help","/company",
         "/impressum","/privacy","/terms","/careers","/jobs"]

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
MAILTO_RE = re.compile(r"mailto:([^\"'>?\s]+)")

class EmailHarvest:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        emails = set()

        def scrape(path):
            r = http.get(base + path)
            if not r: return set()
            found = set(EMAIL_RE.findall(r.text))
            found |= set(MAILTO_RE.findall(r.text))
            return found

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(scrape, p) for p in PAGES]
            for f in as_completed(futs):
                emails |= f.result()

        # filter own site noise (jpg@2x.png false positives)
        emails = {e for e in emails if not re.search(r"\.(png|jpg|jpeg|gif|webp|svg)$", e.lower())}
        for e in sorted(emails)[:30]:
            print(f"  [+] {e}")
            logger.finding("email","info",e)
        print(f"[email_harvest] {len(emails)} unique emails")
        return {"emails": sorted(emails)}
