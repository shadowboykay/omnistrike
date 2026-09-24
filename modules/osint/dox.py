"""dox — aggregate public OSINT on a person/handle via public sources"""
from core.http import HttpClient
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCES = {
    "github":     "https://api.github.com/users/{q}",
    "reddit":     "https://www.reddit.com/user/{q}/about.json",
    "hackernews": "https://hacker-news.firebaseio.com/v0/user/{q}.json",
    "gitlab":     "https://gitlab.com/api/v4/users?username={q}",
}

class Dox:
    def run(self, session, logger):
        q = session.target.strip().lstrip("@")
        http = HttpClient(session, logger)
        print(f"[dox] aggregating public data for '{q}'")
        results = {}

        def fetch(item):
            name, tpl = item
            url = tpl.format(q=q)
            r = http.get(url, headers={"Accept":"application/json","User-Agent":"omni-osint"})
            if not r or r.status_code != 200: return name, None
            try: return name, r.json()
            except Exception: return name, None

        with ThreadPoolExecutor(max_workers=4) as ex:
            for f in as_completed([ex.submit(fetch, it) for it in SOURCES.items()]):
                name, data = f.result()
                if data:
                    results[name] = data
                    print(f"  [+] {name}")
                    logger.finding("dox","info",f"{name}: {str(data)[:120]}")

        print(f"[dox] {len(results)}/{len(SOURCES)} sources")
        return {"query": q, "results": results}
