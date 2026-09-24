# core/http.py — HTTP client: auto-mutate URL+POST, UA rotate, adaptive throttle
import random, time, requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from core.mutator import mutate_url_query, mutate_post_body, mutate_headers

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
]

BLOCK_CODES = (403, 406, 429, 501, 503)


class HttpClient:
    def __init__(self, session, logger=None, auto_mutate=True, adaptive_throttle=True):
        self.session = session
        self.logger = logger
        self.counter = 0
        self.live = True
        self.auto_mutate = auto_mutate
        self.adaptive_throttle = adaptive_throttle
        self.s = requests.Session()
        retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[502, 503])
        self.s.mount("http://", HTTPAdapter(max_retries=retry))
        self.s.mount("https://", HTTPAdapter(max_retries=retry))
        if session.proxy:
            self.s.proxies = {"http": session.proxy, "https": session.proxy}
        self.s.verify = False
        import urllib3; urllib3.disable_warnings()

        # adaptive throttle state
        self._min_delay = 0.0
        self._cur_delay = 0.0
        self._max_delay = 5.0
        self._backoff_factor = 2.0
        self._recover_factor = 0.8

    def _headers(self, extra=None):
        h = {"User-Agent": self.session.user_agent or random.choice(USER_AGENTS)}
        for x in getattr(self.session, "extra", []):
            if x.startswith("cookie="):
                h["Cookie"] = x[7:]
        if extra:
            h.update(extra)
        return h

    def _throttle_sleep(self):
        if self.adaptive_throttle and self._cur_delay > 0:
            time.sleep(self._cur_delay + random.uniform(0, self._cur_delay * 0.3))

    def _throttle_on_block(self):
        if not self.adaptive_throttle:
            return
        self._cur_delay = min(self._cur_delay * self._backoff_factor + 0.5, self._max_delay)
        if self.live:
            print(f"    ⏸ throttle backoff -> {self._cur_delay:.2f}s", flush=True)

    def _throttle_on_success(self):
        if not self.adaptive_throttle:
            return
        self._cur_delay = max(self._cur_delay * self._recover_factor - 0.05, self._min_delay)

    def get(self, url, **kw):
        return self._req("GET", url, **kw)

    def post(self, url, **kw):
        return self._req("POST", url, **kw)

    def _req(self, method, url, headers=None, params=None, data=None, json=None,
             allow_redirects=True, stream=False, label=None, auto_mutate=None):
        mutate_enabled = self.auto_mutate if auto_mutate is None else auto_mutate

        # adaptive throttle wait
        self._throttle_sleep()

        r = self._send(method, url, headers, params, data, json,
                       allow_redirects, stream, label)
        if not r:
            return None

        if r.status_code in BLOCK_CODES:
            self._throttle_on_block()
        else:
            self._throttle_on_success()

        # auto-mutate on block
        if mutate_enabled and r.status_code in BLOCK_CODES:
            if self.live:
                print(f"    ↻ #{self.counter} blocked {r.status_code}, auto-mutating...", flush=True)

            # 1. mutate URL query params
            if "?" in url:
                for m_url, p_name, m_val in mutate_url_query(url, n=6):
                    r2 = self._send(method, m_url, headers, params, data, json,
                                    allow_redirects, stream, label=f"mut-url {p_name}")
                    if r2 and r2.status_code not in BLOCK_CODES:
                        if self.live:
                            print(f"    ✓ auto-mutate URL: {p_name}={m_val[:30]} -> {r2.status_code}", flush=True)
                        if self.logger:
                            self.logger.info("auto_mutate_url", param=p_name,
                                             original=r.status_code, new=r2.status_code)
                        return r2

            # 2. mutate POST body
            if method.upper() == "POST" and (data is not None or json is not None):
                body = data if data is not None else json
                for m_body, f_name, m_val in mutate_post_body(body, n=6):
                    r2 = self._send(method, url, headers, params,
                                    m_body if data is not None else None,
                                    m_body if json is not None else None,
                                    allow_redirects, stream, label=f"mut-body {f_name}")
                    if r2 and r2.status_code not in BLOCK_CODES:
                        if self.live:
                            print(f"    ✓ auto-mutate BODY: {f_name}={m_val[:30]} -> {r2.status_code}", flush=True)
                        if self.logger:
                            self.logger.info("auto_mutate_body", field=f_name,
                                             original=r.status_code, new=r2.status_code)
                        return r2

            # 3. mutate headers (UA rotation + IP spoof)
            for m_headers, desc in mutate_headers(headers or {}, n=2):
                r2 = self._send(method, url, m_headers, params, data, json,
                                allow_redirects, stream, label=f"mut-hdr {desc[:20]}")
                if r2 and r2.status_code not in BLOCK_CODES:
                    if self.live:
                        print(f"    ✓ auto-mutate HEADER: {desc} -> {r2.status_code}", flush=True)
                    if self.logger:
                        self.logger.info("auto_mutate_header", change=desc,
                                         original=r.status_code, new=r2.status_code)
                    return r2

            if self.live:
                print(f"    · auto-mutate failed after all variants", flush=True)

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
                delay = f" ⏸{self._cur_delay:.1f}s" if self._cur_delay > 0.5 else ""
                print(f"    {mark} #{self.counter} {code} {dt:.2f}s {size}b{delay}{tag}", flush=True)
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
