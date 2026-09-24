"""swarm_mode v2 — 20 parallel identities + auto-differential analysis"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient
from core.session import Session
import time
import random


# 20 distinct identities: 5 browsers × 2 platforms × 2 crawlers
STRATEGIES = {
    # Browsers
    "chrome_win":    {"delay": 0.1, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36", "headers": {"sec-ch-ua": '"Chromium";v="120"'}},
    "chrome_mac":    {"delay": 0.1, "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"},
    "chrome_linux":  {"delay": 0.1, "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"},
    "chrome_android":{"delay": 0.1, "ua": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36"},
    "chrome_ios":    {"delay": 0.1, "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 CriOS/120.0 Mobile Safari/604.1"},

    "firefox_win":   {"delay": 0.1, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"},
    "firefox_mac":   {"delay": 0.1, "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"},
    "firefox_linux": {"delay": 0.1, "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"},
    "firefox_android":{"delay": 0.1, "ua": "Mozilla/5.0 (Android 13; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0"},

    "safari_mac":    {"delay": 0.1, "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15"},
    "safari_ios":    {"delay": 0.1, "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1"},
    "safari_ipad":   {"delay": 0.1, "ua": "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1"},

    "edge_win":      {"delay": 0.1, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 Edg/120.0"},
    "opera_win":     {"delay": 0.1, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 OPR/105.0"},

    # Mobile apps
    "instagram":     {"delay": 0.5, "ua": "Instagram 250.0.0.20.111 Android"},
    "whatsapp":      {"delay": 0.5, "ua": "WhatsApp/2.23.20.0 Android"},
    "telegram":      {"delay": 0.5, "ua": "TelegramBot (like TwitterBot)"},

    # Crawlers
    "googlebot":     {"delay": 2.0, "ua": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "headers": {"From": "googlebot(at)googlebot.com"}},
    "bingbot":       {"delay": 2.0, "ua": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"},

    # SEO tools (often whitelisted)
    "semrushbot":    {"delay": 0.5, "ua": "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)"},
    "ahrefsbot":     {"delay": 0.5, "ua": "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"},
}


class SwarmMode:
    def run(self, session, logger):
        target = session.target
        print(f"[swarm] target: {target}")
        print(f"[swarm] launching {len(STRATEGIES)} identities in parallel")
        print()

        def probe(name, cfg):
            sub = Session(target=target, timeout=20)
            sub.user_agent = cfg["ua"]
            h = HttpClient(sub, None)
            time.sleep(cfg.get("delay", 0))
            t0 = time.time()
            r = h.get(target, headers=cfg.get("headers"))
            dt = time.time() - t0
            return {
                "name": name,
                "code": r.status_code if r else None,
                "size": len(r.content) if r else 0,
                "time": round(dt, 2),
                "server": r.headers.get("Server", "")[:40] if r else "",
                "cf_ray": bool(r and "cf-ray" in r.headers) if r else False,
                "waf_hit": bool(r and r.status_code in (403, 406, 429, 503)),
            }

        results = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(probe, n, c): n for n, c in STRATEGIES.items()}
            for f in as_completed(futs):
                r = f.result()
                results.append(r)
                mark = "!" if r["waf_hit"] else "+"
                print(f"  {mark} {r['name']:16s} {str(r['code']):4s} "
                      f"{r['size']:6d}b {r['time']:5.2f}s {r['server']}")

        # analysis
        print()
        print("=" * 60)
        print("[swarm] DIFFERENTIAL ANALYSIS")
        print("=" * 60)

        codes = {}
        for r in results:
            codes.setdefault(r["code"], []).append(r["name"])

        sizes = {}
        for r in results:
            sizes.setdefault(r["size"], []).append(r["name"])

        print(f"\nCodes distribution:")
        for code, names in sorted(codes.items(), key=lambda x: -len(x[1])):
            mark = "!"
            print(f"  {mark} {code}: {len(names)} ({', '.join(names[:3])}{'...' if len(names) > 3 else ''})")

        if len(sizes) > 1:
            print(f"\n! Response size varies: {len(sizes)} different sizes")
            for size, names in sorted(sizes.items(), key=lambda x: -len(x[1]))[:3]:
                print(f"  {size}b: {len(names)} identities")

        # key finding: which identities get different response
        blocked = [r for r in results if r["waf_hit"]]
        allowed = [r for r in results if not r["waf_hit"] and r["code"] == 200]

        if blocked and allowed:
            print(f"\n! WAF detects {len(blocked)}, allows {len(allowed)}")
            print(f"  BLOCKED: {', '.join(r['name'] for r in blocked[:5])}")
            print(f"  ALLOWED: {', '.join(r['name'] for r in allowed[:5])}")
            print(f"  → используй идентичность из ALLOWED для обхода")
            logger.finding("swarm_waf_bypass", "high",
                           f"blocked: {[r['name'] for r in blocked]}, "
                           f"allowed: {[r['name'] for r in allowed]}")

        if not blocked:
            print(f"\n. no identities blocked — WAF отсутствует или толерантен")

        print(f"\n[swarm] summary: {len(results)} tested, {len(blocked)} blocked")
        logger.finding("swarm_done", "info",
                       f"{len(results)} identities, {len(blocked)} blocked")

        return {"results": results, "blocked": [r["name"] for r in blocked],
                "allowed": [r["name"] for r in allowed]}
