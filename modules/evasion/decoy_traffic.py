"""decoy_traffic v2 — realistic session simulation, not predictable paths"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient
from core.session import Session
import random
import time


# Realistic browsing session templates
SESSIONS = [
    # Pattern 1: search + browse
    ["/", "/search?q={random_word}", "/product/{random_id}", "/", "/about"],
    # Pattern 2: blog reader
    ["/", "/blog", "/blog/post-{random_id}", "/blog", "/"],
    # Pattern 3: contact form visitor
    ["/", "/contact", "/", "/about", "/"],
    # Pattern 4: static assets (browser cache warmup)
    ["/", "/favicon.ico", "/css/main.css", "/js/app.js", "/images/logo.png"],
    # Pattern 5: user login then browse
    ["/", "/login", "/", "/account", "/settings"],
    # Pattern 6: e-commerce
    ["/", "/products", "/products/{random_id}", "/cart", "/checkout"],
    # Pattern 7: news reader
    ["/", "/news", "/news/{random_id}", "/", "/news"],
    # Pattern 8: API explorer
    ["/", "/api/status", "/api/version", "/docs", "/"],
]

REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.facebook.com/",
    "https://twitter.com/",
    "https://www.reddit.com/",
    "https://news.ycombinator.com/",
]

RANDOM_WORDS = [
    "pricing", "features", "integration", "docs", "api",
    "security", "login", "signup", "blog", "about",
    "contact", "support", "careers", "investors",
]


class DecoyTraffic:
    def run(self, session, logger):
        target = session.target
        base = target.rstrip("/")
        print(f"[decoy] target: {target}")
        print(f"[decoy] simulating realistic browsing sessions")
        print()

        n_sessions = 5
        sessions_to_run = random.sample(SESSIONS, min(n_sessions, len(SESSIONS)))

        def run_session(session_template):
            """Simulate one browsing session."""
            sub = Session(target=base, timeout=15)
            sub.user_agent = random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            ])
            h = HttpClient(sub, None)
            referer = random.choice(REFERERS)
            visited = []

            for path in session_template:
                # substitute variables
                path = path.replace("{random_id}", str(random.randint(1, 9999)))
                path = path.replace("{random_word}", random.choice(RANDOM_WORDS))

                headers = {"Referer": referer}
                r = h.get(base + path, headers=headers)
                if r:
                    visited.append((path, r.status_code))
                # human-like pause
                time.sleep(random.uniform(0.8, 3.5))
                # update referer to previous page
                referer = base + path

            return {"ua": sub.user_agent[:40], "visited": visited}

        print(f"[decoy] running {len(sessions_to_run)} parallel sessions")
        print()

        results = []
        with ThreadPoolExecutor(max_workers=3) as ex:
            futs = [ex.submit(run_session, s) for s in sessions_to_run]
            for f in as_completed(futs):
                r = f.result()
                results.append(r)
                ok_count = sum(1 for _, code in r["visited"] if code == 200)
                print(f"  + session ({r['ua']}): {len(r['visited'])} requests, {ok_count} OK")

        total_reqs = sum(len(r["visited"]) for r in results)
        print(f"\n[decoy] итого: {total_reqs} запросов в {len(results)} реалистичных сессиях")
        print(f"[decoy] каждый запрос с правильным Referer — выглядит как реальный пользователь")
        print(f"[decoy] SIEM видит нормальный трафик, а не сухие probes")

        logger.finding("decoy_traffic", "info",
                       f"{total_reqs} requests in {len(results)} sessions")
        return {"sessions": len(results), "total_requests": total_reqs}
