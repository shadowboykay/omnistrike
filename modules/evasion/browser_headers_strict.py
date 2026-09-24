"""browser_headers_strict — full realistic browser header set with exact ordering"""
from core.http import HttpClient
from collections import OrderedDict


CHROME_120 = OrderedDict([
    ("Host", "TARGET"),
    ("Connection", "keep-alive"),
    ("Cache-Control", "max-age=0"),
    ("sec-ch-ua", '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", '"Windows"'),
    ("Upgrade-Insecure-Requests", "1"),
    ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-User", "?1"),
    ("Sec-Fetch-Dest", "document"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Accept-Language", "en-US,en;q=0.9"),
])

FIREFOX_121 = OrderedDict([
    ("Host", "TARGET"),
    ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.5"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Connection", "keep-alive"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "none"),
    ("Sec-Fetch-User", "?1"),
])

SAFARI_17 = OrderedDict([
    ("Host", "TARGET"),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Sec-Fetch-Site", "none"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("Sec-Fetch-Dest", "document"),
    ("Sec-Fetch-Mode", "navigate"),
    ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Connection", "keep-alive"),
    ("Sec-Fetch-User", "?1"),
])

SETS = {"chrome_120": CHROME_120, "firefox_121": FIREFOX_121, "safari_17": SAFARI_17}


class BrowserHeadersStrict:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        target = session.target
        host = target.split("//")[-1].split("/")[0].split(":")[0]

        results = []
        for name, tpl in SETS.items():
            headers = {k: (host if v == "TARGET" else v) for k, v in tpl.items()}
            r = http.get(target, headers=headers)
            if not r:
                continue
            print(f"  ✓ {name:12s} {r.status_code} {len(r.content)}b")
            results.append({"browser": name, "code": r.status_code, "size": len(r.content)})
            logger.info("browser_strict", browser=name, code=r.status_code)

        print(f"[browser_headers_strict] {len(results)}/{len(SETS)} browsers tested")
        return {"results": results}
