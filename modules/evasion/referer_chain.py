"""referer_chain — build believable referer chain (search → site → target)"""
from core.http import HttpClient

CHAINS = [
    ["https://www.google.com/search?q=SITE", None],
    ["https://www.bing.com/search?q=SITE", None],
    ["https://yandex.ru/search/?text=SITE", None],
    ["https://duckduckgo.com/?q=SITE", None],
]

class RefererChain:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        domain = session.target.replace("https://","").replace("http://","").split("/")[0]
        base = http.get(session.target)
        base_code = base.status_code if base else None
        base_len = len(base.content) if base else 0
        print(f"[referer_chain] baseline {base_code} ({base_len}b)")

        for chain in CHAINS:
            search = chain[0].replace("SITE", domain)
            r = http.get(session.target, headers={"Referer": search})
            if not r: continue
            diff = abs(len(r.content) - base_len)
            marker = "  [!]" if (r.status_code != base_code or diff > 200) else "     "
            print(f"{marker} {search[:50]} -> {r.status_code} (diff {diff:+d})")
            if r.status_code != base_code:
                logger.finding("referer_bypass","medium",f"{search[:60]} -> {r.status_code}")
        return {}
