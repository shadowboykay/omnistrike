"""header_order_spoof — reorder HTTP headers to match real browser fingerprints"""
from core.http import HttpClient
from collections import OrderedDict


BROWSER_ORDERS = {
    "chrome": ["Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile",
               "sec-ch-ua-platform", "Upgrade-Insecure-Requests", "User-Agent",
               "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User",
               "Sec-Fetch-Dest", "Referer", "Accept-Encoding",
               "Accept-Language", "Cookie"],
    "firefox": ["Host", "User-Agent", "Accept", "Accept-Language",
                "Accept-Encoding", "Connection", "Referer", "Cookie",
                "Upgrade-Insecure-Requests", "Sec-Fetch-Dest",
                "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User"],
    "safari": ["Host", "Accept", "Sec-Fetch-Site", "Cookie",
               "Sec-Fetch-Dest", "Accept-Language", "Sec-Fetch-Mode",
               "User-Agent", "Referer", "Accept-Encoding",
               "Connection", "Sec-Fetch-User"],
}


class HeaderOrderSpoof:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        target = session.target

        for browser, order in BROWSER_ORDERS.items():
            headers = OrderedDict()
            for h in order:
                if h == "User-Agent":
                    headers[h] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
                elif h == "Accept":
                    headers[h] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                elif h == "Accept-Language":
                    headers[h] = "en-US,en;q=0.9"
                elif h == "Accept-Encoding":
                    headers[h] = "gzip, deflate, br"
                elif h == "Connection":
                    headers[h] = "keep-alive"
                elif h.startswith("sec-") or h.startswith("Sec-"):
                    if h == "sec-ch-ua":
                        headers[h] = '"Not_A Brand";v="8", "Chromium";v="120"'
                    elif h == "sec-ch-ua-mobile":
                        headers[h] = "?0"
                    elif h == "sec-ch-ua-platform":
                        headers[h] = '"Windows"'
                    elif h == "Sec-Fetch-Site":
                        headers[h] = "none"
                    elif h == "Sec-Fetch-Mode":
                        headers[h] = "navigate"
                    elif h == "Sec-Fetch-User":
                        headers[h] = "?1"
                    elif h == "Sec-Fetch-Dest":
                        headers[h] = "document"

            r = http.get(target, headers=dict(headers))
            if r:
                code = r.status_code
                size = len(r.content)
                print(f"  ✓ {browser:8s} (order enforced) {code} {size}b")
                logger.info("header_order", browser=browser, code=code)

        print(f"[header_order_spoof] checked {len(BROWSER_ORDERS)} browser orders")
        return {"orders": list(BROWSER_ORDERS.keys())}
