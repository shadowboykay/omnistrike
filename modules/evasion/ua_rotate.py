"""ua_rotate — rotate User-Agent + headers to mimic real browser session"""
import random

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://yandex.ru/",
]

class UaRotate:
    def run(self, session, logger):
        from core.http import HttpClient
        http = HttpClient(session, logger)
        print(f"[ua_rotate] testing {len(UAS)} user-agents")
        results = {}
        for ua in UAS:
            r = http.get(session.target, headers={
                "User-Agent": ua,
                "Referer": random.choice(REFERERS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "DNT": "1",
                "Upgrade-Insecure-Requests": "1",
            })
            code = r.status_code if r else None
            results[ua[:40]] = code
            print(f"  {code} <- {ua[:50]}")
        return {"results": results}
