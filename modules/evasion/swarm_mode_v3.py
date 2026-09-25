"""swarm_mode_v3 — 50 identities with auto-bypass detection"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient
from core.session import Session
import time


def gen_identities():
    """Generate 50 distinct identities."""
    out = {}

    # Browsers (desktop) — 20
    for os_name, os_ua in [
        ("win", "Windows NT 10.0; Win64; x64"),
        ("mac", "Macintosh; Intel Mac OS X 10_15_7"),
        ("lin", "X11; Linux x86_64"),
        ("win11", "Windows NT 11.0; Win64; x64"),
    ]:
        for browser, ver in [
            ("chrome", "120.0"), ("chrome", "121.0"),
            ("firefox", "121.0"), ("edge", "120.0"),
            ("opera", "105.0"),
        ]:
            key = f"{browser}_{ver.split('.')[0]}_{os_name}"
            if browser == "firefox":
                ua = f"Mozilla/5.0 ({os_ua}; rv:{ver}) Gecko/20100101 Firefox/{ver}"
            elif browser == "edge":
                ua = f"Mozilla/5.0 ({os_ua}) AppleWebKit/537.36 Chrome/{ver} Safari/537.36 Edg/{ver}"
            elif browser == "opera":
                ua = f"Mozilla/5.0 ({os_ua}) AppleWebKit/537.36 Chrome/{ver} Safari/537.36 OPR/{ver}"
            else:
                ua = f"Mozilla/5.0 ({os_ua}) AppleWebKit/537.36 Chrome/{ver} Safari/537.36"
            out[key] = {"ua": ua, "delay": 0.1}

    # Mobile browsers — 8
    for device, ua in [
        ("iphone_17", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1"),
        ("ipad_17", "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1"),
        ("android_13_chrome", "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0.6099.144 Mobile Safari/537.36"),
        ("android_13_firefox", "Mozilla/5.0 (Android 13; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0"),
        ("android_14_samsung", "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36"),
        ("android_12_xiaomi", "Mozilla/5.0 (Linux; Android 12; M2101K7BG) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36"),
        ("iphone_16", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 Version/16.6 Mobile/15E148 Safari/604.1"),
        ("android_11", "Mozilla/5.0 (Linux; Android 11) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36"),
    ]:
        out[f"mobile_{device}"] = {"ua": ua, "delay": 0.3}

    # Crawlers — 8
    for name, ua in [
        ("googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
        ("googlebot_mobile", "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
        ("bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
        ("yandexbot", "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"),
        ("duckduckbot", "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)"),
        ("baiduspider", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"),
        ("applebot", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)"),
        ("yeti", "Mozilla/5.0 (compatible; Yeti/1.1; +http://naver.me/spd)"),
    ]:
        out[f"crawler_{name}"] = {"ua": ua, "delay": 1.5}

    # SEO tools — 6
    for name, ua in [
        ("semrush", "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)"),
        ("ahrefs", "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"),
        ("mj12", "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)"),
        ("dotbot", "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)"),
        ("screamingfrog", "Screaming Frog SEO Spider/19.2"),
        ("petalbot", "Mozilla/5.0 (compatible;PetalBot;+https://webmaster.petalsearch.com/site/petalbot)"),
    ]:
        out[f"seo_{name}"] = {"ua": ua, "delay": 0.5}

    # Social media — 4
    for name, ua in [
        ("facebook", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"),
        ("twitter", "Twitterbot/1.0"),
        ("whatsapp", "WhatsApp/2.23.20.0"),
        ("telegram", "TelegramBot (like TwitterBot)"),
    ]:
        out[f"social_{name}"] = {"ua": ua, "delay": 0.5}

    # Mobile apps — 4
    for name, ua in [
        ("instagram", "Instagram 250.0.0.20.111 Android"),
        ("linkedin", "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)"),
        ("slack", "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"),
        ("discord", "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"),
    ]:
        out[f"app_{name}"] = {"ua": ua, "delay": 0.5}

    return out


STRATEGIES = gen_identities()


class SwarmModeV3:
    def run(self, session, logger):
        target = session.target
        print(f"[swarm v3] target: {target}")
        print(f"[swarm v3] {len(STRATEGIES)} identities")
        print()

        def probe(name, cfg):
            sub = Session(target=target, timeout=15)
            sub.user_agent = cfg["ua"]
            h = HttpClient(sub, None)
            time.sleep(cfg["delay"])
            try:
                r = h.get(target)
                return {
                    "name": name,
                    "code": r.status_code if r else None,
                    "size": len(r.content) if r else 0,
                    "server": r.headers.get("Server", "")[:30] if r else "",
                    "waf_hit": bool(r and r.status_code in (403, 406, 429, 503)),
                }
            except Exception:
                return {"name": name, "code": None, "size": 0, "server": "", "waf_hit": False}

        results = []
        with ThreadPoolExecutor(max_workers=15) as ex:
            futs = {ex.submit(probe, n, c): n for n, c in STRATEGIES.items()}
            for f in as_completed(futs):
                results.append(f.result())

        # summary
        codes = {}
        for r in results:
            codes.setdefault(r["code"], []).append(r["name"])

        print("=" * 60)
        print("RESULTS BY CODE")
        print("=" * 60)
        for code, names in sorted(codes.items(), key=lambda x: -len(x[1])):
            marker = "!" if code in (403, 406, 429, 503) else " "
            print(f"  {marker} {code}: {len(names):3d} identities")

        # auto-bypass
        allowed = [r for r in results if r["code"] == 200]
        blocked = [r for r in results if r["waf_hit"]]

        if blocked and allowed:
            print()
            print("=" * 60)
            print("! WAF BYPASS FOUND")
            print("=" * 60)
            print(f"  blocked: {len(blocked)} identities")
            print(f"  allowed: {len(allowed)} identities")
            print()
            print("  лучшие identity для обхода (200 OK):")
            for r in allowed[:10]:
                print(f"    + {r['name']:30s}")
            print()
            print("  заблокированы (не использовать):")
            for r in blocked[:5]:
                print(f"    - {r['name']:30s}")

            logger.finding("swarm_bypass", "critical",
                           f"{len(allowed)} identities bypass WAF")
        elif not blocked:
            print(f"\n. no identities blocked — WAF отсутствует")
        else:
            print(f"\n! all identities blocked — WAF агрессивный")

        print(f"\n[swarm v3] summary: {len(results)} tested")
        return {"total": len(results), "allowed": [r["name"] for r in allowed],
                "blocked": [r["name"] for r in blocked]}
