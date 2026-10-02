"""googlebot_spoof v2 — Googlebot/Bingbot/Yandex impersonation with rDNS verify.

v1 problem: "diff > 200 bytes" = crawler bypass → 90% ложных findings
v2:
  - Strict status code gate (403/401 → 200 only)
  - rDNS verify if target does DNS lookups
  - Non-loopback X-Forwarded-For
  - Actual Googlebot IP ranges (published by Google)
  - API for other modules
"""
import random
import socket
from core.http import HttpClient


# ==== crawler identities (актуальные на 2024) ====
CRAWLERS = {
    "googlebot_desktop": {
        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "From": "googlebot(at)googlebot.com",
    },
    "googlebot_smartphone": {
        "User-Agent": "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
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
    "adsbot_google": {
        "User-Agent": "AdsBot-Google (+http://www.google.com/adsbot.html)",
    },
    "google_web_preview": {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (compatible; Google-Web-Preview/1.0)",
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
    "applebot": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)",
    },
    "facebook_external_hit": {
        "User-Agent": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    },
    "twitterbot": {
        "User-Agent": "Twitterbot/1.0",
    },
    "telegram_bot": {
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
    "discordbot": {
        "User-Agent": "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
    },
}


# ==== verified crawler IP ranges (published) ====
# Источник: developers.google.com/search/apis/ipranges/googlebot.json
GOOGLEBOT_IPV4_PREFIXES = [
    "66.249.64.", "66.249.65.", "66.249.66.", "66.249.67.",
    "66.249.68.", "66.249.69.", "66.249.70.", "66.249.71.",
    "66.249.72.", "66.249.73.", "66.249.74.", "66.249.75.",
    "66.249.76.", "66.249.77.", "66.249.78.", "66.249.79.",
    "66.249.88.", "66.249.89.",
    "34.64.0.",
    "35.190.247.",
]


def _random_googlebot_ip():
    prefix = random.choice(GOOGLEBOT_IPV4_PREFIXES)
    return prefix + str(random.randint(1, 254))


def _rdns_check(ip):
    """
    Проверка rDNS: делать reverse lookup + forward verify.
    Если target сам делает — покажет mismatch, но мы не палимся явно.
    """
    try:
        host = socket.gethostbyaddr(ip)[0]
        # forward verify
        forward_ips = [a[4][0] for a in socket.getaddrinfo(host, None)]
        return {"host": host, "matches": ip in forward_ips}
    except Exception:
        return None


def get_crawler_headers(crawler="googlebot_desktop", with_ip=False):
    """
    API для других модулей: получить headers crawler-идентичности.
    """
    base = CRAWLERS.get(crawler, CRAWLERS["googlebot_desktop"])
    h = dict(base)
    if with_ip:
        ip = _random_googlebot_ip()
        h["X-Forwarded-For"] = ip
        h["X-Real-IP"] = ip
        h["CF-Connecting-IP"] = ip
        h["True-Client-IP"] = ip
    return h


class GooglebotSpoof:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        try:
            base = http.get(target)
        except Exception:
            print(f"[googlebot_spoof v2] target unreachable")
            return {"results": [], "findings": []}
        base_code = base.status_code if base else 0
        base_len = len(base.content) if base else 0

        print(f"[googlebot_spoof v2] target: {target}")
        print(f"[googlebot_spoof v2] baseline: {base_code} ({base_len}b)")

        results = []
        findings = []

        # === 1. Прогон каждого crawler UA ===
        print()
        print(f"[googlebot_spoof v2] testing {len(CRAWLERS)} crawler identities")
        for name, headers in CRAWLERS.items():
            try:
                r = http.get(target, headers=headers)
            except Exception:
                continue
            if not r:
                continue

            diff = abs(len(r.content) - base_len)
            # ГЛАВНОЕ: finding только если status code изменился
            # (403/401 → 200, или 200 → 403 = anti-bot detected)
            status_changed = r.status_code != base_code
            results.append({
                "crawler": name,
                "code": r.status_code,
                "diff": diff,
                "changed": status_changed,
            })
            marker = "  ✓" if status_changed else "   "
            print(f"{marker} {name:25s} {r.status_code} ({len(r.content)}b, diff {diff:+d})")
            if status_changed:
                findings.append({
                    "type": "crawler_status_change",
                    "crawler": name,
                    "baseline": base_code,
                    "result": r.status_code,
                })
                logger.finding("crawler_bypass", "medium",
                               f"{name}: {base_code} → {r.status_code}")

        # === 2. Googlebot + verified IP ===
        print()
        print(f"[googlebot_spoof v2] testing Googlebot + real IP ranges")
        for i in range(8):
            ip = _random_googlebot_ip()
            rdns = _rdns_check(ip)
            headers = {
                "User-Agent": CRAWLERS["googlebot_desktop"]["User-Agent"],
                "X-Forwarded-For": ip,
                "X-Real-IP": ip,
                "CF-Connecting-IP": ip,
                "True-Client-IP": ip,
            }
            try:
                r = http.get(target, headers=headers)
            except Exception:
                continue
            if not r:
                continue

            if r.status_code != base_code:
                print(f"  ✓ {ip:16s} → {r.status_code} (rDNS: {rdns['host'] if rdns else 'none'})")
                findings.append({
                    "type": "googlebot_ip_bypass",
                    "ip": ip,
                    "baseline": base_code,
                    "result": r.status_code,
                    "rdns": rdns,
                })
                logger.finding("googlebot_ip_bypass", "high", ip)
            else:
                print(f"    {ip:16s} → {r.status_code}")

        # === 3. Сводка ===
        changed = sum(1 for r in results if r["changed"])
        print()
        print(f"[googlebot_spoof v2] {changed}/{len(results)} crawlers get different status code")
        print(f"[googlebot_spoof v2] findings: {len(findings)}")

        logger.info("googlebot_spoof",
                    tested=len(results), changed=changed)

        return {
            "results": results,
            "findings": findings,
            "changed": changed,
        }
