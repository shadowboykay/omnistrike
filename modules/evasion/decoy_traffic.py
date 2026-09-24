"""decoy_traffic — send harmless decoy requests to hide real activity in logs"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient
from core.session import Session
import random
import time


DECOY_PATHS = [
    "/robots.txt", "/sitemap.xml", "/favicon.ico",
    "/.well-known/security.txt", "/humans.txt",
    "/blog", "/news", "/about", "/contact",
    "/images/logo.png", "/css/style.css", "/js/app.js",
    "/api/status", "/health", "/ping",
    "/static/media/photo.jpg",
    "/legacy/index.html", "/old-site/",
]

DECOY_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "facebookexternalhit/1.1",
    "Twitterbot/1.0",
]


class DecoyTraffic:
    def run(self, session, logger):
        target = session.target
        base = target.rstrip("/")
        print(f"[decoy] target: {target}")
        print(f"[decoy] sending {len(DECOY_PATHS)} harmless requests")
        print()

        def send_decoy(path):
            sub = Session(target=base, timeout=10)
            sub.user_agent = random.choice(DECOY_UAS)
            h = HttpClient(sub, None)
            time.sleep(random.uniform(0, 3))
            try:
                r = h.get(base + path)
                return {"path": path, "code": r.status_code if r else None}
            except Exception:
                return {"path": path, "code": None}

        results = []
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(send_decoy, p) for p in DECOY_PATHS]
            for f in as_completed(futs):
                r = f.result()
                results.append(r)
                print(f"  + {r['code']} {r['path']}")

        ok = sum(1 for r in results if r["code"] == 200)
        print(f"\n[decoy] sent {len(results)} decoys ({ok} valid)")
        print(f"[decoy] цель: замаскировать реальные запросы в логах сервера")
        logger.finding("decoy_traffic", "info", f"{len(results)} decoys sent")
        return {"decoys": len(results), "valid": ok}
