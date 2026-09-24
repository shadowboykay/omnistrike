"""username — check username presence across popular platforms"""
from core.http import HttpClient
from concurrent.futures import ThreadPoolExecutor, as_completed

PLATFORMS = {
    "github":     "https://github.com/{u}",
    "twitter":    "https://twitter.com/{u}",
    "instagram":  "https://www.instagram.com/{u}/",
    "reddit":     "https://www.reddit.com/user/{u}",
    "tiktok":     "https://www.tiktok.com/@{u}",
    "youtube":    "https://www.youtube.com/@{u}",
    "telegram":   "https://t.me/{u}",
    "vk":         "https://vk.com/{u}",
    "pinterest":  "https://www.pinterest.com/{u}/",
    "medium":     "https://medium.com/@{u}",
    "twitch":     "https://www.twitch.tv/{u}",
    "spotify":    "https://open.spotify.com/user/{u}",
    "steam":      "https://steamcommunity.com/id/{u}",
    "gitlab":     "https://gitlab.com/{u}",
    "hackernews": "https://news.ycombinator.com/user?id={u}",
}

class Username:
    def run(self, session, logger):
        u = session.target.strip().lstrip("@")
        http = HttpClient(session, logger)
        print(f"[username] checking '{u}' across {len(PLATFORMS)} platforms")
        found = []

        def check(item):
            name, tpl = item
            r = http.get(tpl.format(u=u), allow_redirects=True)
            if not r: return None
            if r.status_code == 200 and "not found" not in r.text.lower()[:2000]:
                return {"platform": name, "url": tpl.format(u=u)}
            return None

        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = [ex.submit(check, it) for it in PLATFORMS.items()]
            for f in as_completed(futs):
                res = f.result()
                if res:
                    found.append(res)
                    print(f"  [+] {res['platform']:12s} {res['url']}")
                    logger.finding("username","info",f"{res['platform']} {res['url']}")
        print(f"[username] {len(found)}/{len(PLATFORMS)} found")
        return {"username": u, "found": found}
