# core/http.py — HTTP client with per-request live logging
import random, time, requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


class HttpClient:
    def __init__(self, session, logger=None):
        self.session = session
        self.logger = logger
        self.counter = 0
        self.live = True  # показывать каждый запрос
        self.s = requests.Session()
        retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[502,503])
        self.s.mount("http://", HTTPAdapter(max_retries=retry))
        self.s.mount("https://", HTTPAdapter(max_retries=retry))
        if session.proxy:
            self.s.proxies = {"http": session.proxy, "https": session.proxy}
        self.s.verify = False
        import urllib3; urllib3.disable_warnings()

    def _headers(self, extra=None):
        h = {"User-Agent": self.session.user_agent or random.choice(USER_AGENTS)}
        if extra: h.update(extra)
        return h

    def get(self, url, **kw):
        return self._req("GET", url, **kw)

    def post(self, url, **kw):
        return self._req("POST", url, **kw)

    def _req(self, method, url, headers=None, params=None, data=None, json=None,
             allow_redirects=True, stream=False, label=None):
        """
        label: короткая метка payload'а для лога (например "' OR 1=1--")
        """
        self.counter += 1
        t0 = time.time()
        try:
            r = self.s.request(method, url, headers=self._headers(headers),
                params=params, data=data, json=json, timeout=self.session.timeout,
                allow_redirects=allow_redirects, stream=stream)
            dt = time.time() - t0
            if self.live:
                code = r.status_code
                mark = "✓" if code < 400 else "✗"
                size = len(r.content)
                tag = f" [{label[:40]}]" if label else ""
                print(f"    {mark} #{self.counter} {code} {dt:.2f}s {size}b{tag}", flush=True)
            if self.logger:
                self.logger.debug("http", method=method, url=url, code=r.status_code, size=len(r.content))
            return r
        except requests.Timeout:
            dt = time.time() - t0
            tag = f" [{label[:40]}]" if label else ""
            if self.live:
                print(f"    ⏱ #{self.counter} TIMEOUT {dt:.1f}s{tag}", flush=True)
            if self.logger:
                self.logger.warn("http_timeout", url=url, label=label, elapsed=dt)
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

    def close(self): self.s.close()
