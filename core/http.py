# core/http.py — HTTP client with per-request logging + auto-mutation on block
import random, time, requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from core.mutator import mutate_url_query

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

BLOCK_CODES = (403, 406, 429, 501, 503)


class HttpClient:
    def __init__(self, session, logger=None, auto_mutate=True):
        self.session = session
        self.logger = logger
        self.counter = 0
        self.live = True
        self.auto_mutate = auto_mutate
        self.s = requests.Session()
        retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[502, 503])
        self.s.mount("http://", HTTPAdapter(max_retries=retry))
        self.s.mount("https://", HTTPAdapter(max_retries=retry))
        if session.proxy:
            self.s.proxies = {"http": session.proxy, "https": session.proxy}
        self.s.verify = False
        import urllib3; urllib3.disable_warnings()

    def _headers(self, extra=None):
        h = {"User-Agent": self.session.user_agent or random.choice(USER_AGENTS)}
        # cookie from --extra cookie=...
        for x in getattr(self.session, "extra", []):
            if x.startswith("cookie="):
                h["Cookie"] = x[7:]
        if extra:
            h.update(extra)
        return h

    def get(self, url, **kw):
        return self._req("GET", url, **kw)

    def post(self, url, **kw):
        return self._req("POST", url, **kw)

    def _req(self, method, url, headers=None, params=None, data=None, json=None,
             allow_redirects=True, stream=False, label=None, auto_mutate=None):
        """
        label: short payload tag for log
        auto_mutate: override instance default; if True and response is 403/406/429,
                     retry with mutated query params
        """
        mutate_enabled = self.auto_mutate if auto_mutate is None else auto_mutate

        r = self._send(method, url, headers, params, data, json, allow_redirects, stream, label)
        if not r:
            return None

        if mutate_enabled and r.status_code in BLOCK_CODES and "?" in url:
            if self.live:
                print(f"    ↻ #{self.counter} blocked {r.status_code}, auto-mutating...", flush=True)
            for m_url, p_name, m_val in mutate_url_query(url, n=6):
                r2 = self._send(method, m_url, headers, params, data, json,
                                allow_redirects, stream, label=f"mut {p_name}")
                if r2 and r2.status_code not in BLOCK_CODES:
                    if self.live:
                        print(f"    ✓ auto-mutate bypass: {p_name}={m_val[:30]} -> {r2.status_code}", flush=True)
                    if self.logger:
                        self.logger.info("auto_mutate_bypass", param=p_name,
                                         original=r.status_code, new=r2.status_code)
                    return r2
            if self.live:
                print(f"    · auto-mutate failed", flush=True)
        return r

    def _send(self, method, url, headers, params, data, json,
              allow_redirects, stream, label):
        self.counter += 1
        t0 = time.time()
        try:
            r = self.s.request(
                method, url,
                headers=self._headers(headers),
                params=params, data=data, json=json,
                timeout=self.session.timeout,
                allow_redirects=allow_redirects,
                stream=stream,
            )
            dt = time.time() - t0
            if self.live:
                code = r.status_code
                mark = "✓" if code < 400 else ("✗" if code not in BLOCK_CODES else "🛑")
                size = len(r.content)
                tag = f" [{label[:40]}]" if label else ""
                print(f"    {mark} #{self.counter} {code} {dt:.2f}s {size}b{tag}", flush=True)
            if self.logger:
                self.logger.debug("http", method=method, url=url,
                                  code=r.status_code, size=len(r.content))
            return r
        except requests.Timeout:
            dt = time.time() - t0
            tag = f" [{label[:40]}]" if label else ""
            if self.live:
                print(f"    ⏱ #{self.counter} TIMEOUT {dt:.1f}s{tag}", flush=True)
            return None
        except requests.ConnectionError:
            dt = time.time() - t0
            if self.live:
                tag = f" [{label[:40]}]" if label else ""
                print(f"    ⚡ #{self.counter} CONN-ERR {dt:.1f}s{tag}", flush=True)
            return None
        except requests.RequestException as e:
            if self.live:
                print(f"    ✗ #{self.counter} ERR {type(e).__name__}: {str(e)[:60]}", flush=True)
            return None

    def close(self):
        self.s.close()
