"""googlebot_spoof — impersonate Googlebot/Bingbot/Yandex crawlers (full header set + IP spoof option)"""
import random
from core.http import HttpClient

CRAWLERS = {
    "googlebot_desktop": {
        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "From": "googlebot(at)googlebot.com",
    },
    "googlebot_smartphone": {
        "User-Agent": "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    },
    "googlebot_image": {
        "User-Agent": "Googlebot-Image/1.0",
    },
    "googlebot_news": {
        "User-Agent": "Googlebot-News",
    },
    "googlebot_video": {
        "User-Agent": "Googlebot-Video/1.0",
    },
    "google_site_verifier": {
        "User-Agent": "Mozilla/5.0 (compatible; Google-Site-Verification/1.0)",
    },
    "google_web_preview": {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 (compatible; Google-Web-Preview/1.0)",
    },
    "google_adsbot": {
        "User-Agent": "AdsBot-Google (+http://www.google.com/adsbot.html)",
    },
    "bingbot": {
        "User-Agent": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    },
    "yandexbot": {
        "User-Agent": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    },
    "duckduckbot": {
        "User-Agent": "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    },
    "baiduspider": {
        "User-Agent": "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    },
    "facebook_external_hit": {
        "User-Agent": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    },
    "twitterbot": {
        "User-Agent": "Twitterbot/1.0",
    },
    "telegrambot": {
        "User-Agent": "TelegramBot (like TwitterBot)",
    },
    "whatsapp": {
        "User-Agent": "WhatsApp/2.23.20.0",
    },
    "linkedinbot": {
        "User-Agent": "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
    },
    "slackbot": {
        "User-Agent": "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
    },
    "applebot": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)",
    },
    "discordbot": {
        "User-Agent": "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
    },
}

# Googlebot reverse DNS ranges (to appear legit if target does rDNS)
GOOGLEBOT_VERIFIED_RANGES = [
    "66.249.64.", "66.249.65.", "66.249.66.", "66.249.67.", "66.249.68.",
    "66.249.69.", "66.249.70.", "66.249.71.", "66.249.72.", "66.249.73.",
    "66.249.74.", "66.249.75.", "66.249.76.", "66.249.77.", "66.249.78.",
    "66.249.79.", "66.249.80.", "66.249.81.", "66.249.82.", "66.249.83.",
    "66.249.88.", "66.249.89.", "66.249.90.", "66.249.91.", "66.249.92.",
    "66.249.93.", "34.64.0.0", "35.247.", "35.190.", "192.178.",
]


class GooglebotSpoof:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        base = http.get(session.target)
        base_code = base.status_code if base else None
        base_len = len(base.content) if base else 0
        print(f"[googlebot_spoof] baseline: {base_code} ({base_len}b)")
        print(f"[googlebot_spoof] testing {len(CRAWLERS)} crawler identities")

        results = []
        for name, headers in CRAWLERS.items():
            r = http.get(session.target, headers=headers)
            if not r: continue
            diff = abs(len(r.content) - base_len)
            changed = r.status_code != base_code or diff > 200
            results.append({"crawler":name, "code":r.status_code, "diff":diff, "changed":changed})
            marker = "  [!]" if changed else "     "
            print(f"{marker} {name:24s} {r.status_code} ({len(r.content)}b, diff {diff:+d})")
            if changed:
                logger.finding("crawler_bypass","medium",f"{name} -> {r.status_code} diff={diff}")

        # try verified Googlebot IP ranges via X-Forwarded-For
        print()
        print("[googlebot_spoof] trying verified-IP spoofing")
        for ip_range in GOOGLEBOT_VERIFIED_RANGES[:8]:
            ip = ip_range + "1"
            r = http.get(session.target, headers={
                "User-Agent": CRAWLERS["googlebot_desktop"]["User-Agent"],
                "X-Forwarded-For": ip,
                "X-Real-IP": ip,
                "CF-Connecting-IP": ip,
                "True-Client-IP": ip,
            })
            if r and (r.status_code != base_code or abs(len(r.content) - base_len) > 200):
                print(f"  [!] {ip} -> {r.status_code} ({len(r.content)}b)")
                logger.finding("googlebot_ip_bypass","high",f"{ip}")

        changed_count = sum(1 for r in results if r["changed"])
        print(f"\n[googlebot_spoof] {changed_count}/{len(results)} crawlers get different response")
        return {"results": results, "changed": changed_count}
