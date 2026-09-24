"""header_full_spoof — full browser header set + HTTP/1.0 downgrade + Accept-Language spoof"""
from core.http import HttpClient

BROWSER_HEADERS = {
    "chrome_windows": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "max-age=0",
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    "firefox_linux": {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    "safari_mac": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-us",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
    },
    "mobile_ios": {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    },
}

class HeaderFullSpoof:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        base = http.get(session.target)
        base_code = base.status_code if base else None
        base_len = len(base.content) if base else 0
        print(f"[header_full_spoof] baseline {base_code} ({base_len}b)")

        for name, hdrs in BROWSER_HEADERS.items():
            r = http.get(session.target, headers=hdrs)
            if not r: continue
            diff = abs(len(r.content) - base_len)
            changed = r.status_code != base_code or diff > 200
            marker = "  [!]" if changed else "     "
            print(f"{marker} {name:18s} {r.status_code} ({len(r.content)}b, diff {diff:+d})")
            if changed:
                logger.finding("header_spoof_full","medium",f"{name} {base_code}->{r.status_code}")

        # Accept-Language per country
        print()
        print("[header_full_spoof] accept-language per country")
        for lang in ["en-US,en;q=0.9","ru-RU,ru;q=0.9","zh-CN,zh;q=0.9","de-DE,de;q=0.9","fr-FR,fr;q=0.9","ja-JP,ja;q=0.9"]:
            r = http.get(session.target, headers={"Accept-Language": lang})
            if r and abs(len(r.content) - base_len) > 200:
                print(f"  [!] {lang} -> {len(r.content)}b (diff {len(r.content)-base_len:+d})")
                logger.finding("lang_spoof","low",lang)
        return {}
