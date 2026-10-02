# core/http.py — HTTP client: auto-mutate URL+POST, UA rotate, adaptive throttle
import random, time, requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from core.mutator import mutate_url_query, mutate_post_body, mutate_headers

# === современный Chrome fingerprint (2024-2025) ===
# UA синхронизированы с Sec-CH-UA ниже
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

# полный набор Chrome-заголовков — как у настоящего браузера
CHROME_FINGERPRINT = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Ch-Ua-Platform-Version": '"15.0.0"',
    "Sec-Ch-Ua-Arch": '"x86"',
    "Sec-Ch-Ua-Bitness": '"64"',
    "Sec-Ch-Ua-Full-Version": '"124.0.6367.91"',
    "Sec-Ch-Ua-Full-Version-List": '"Chromium";v="124.0.6367.91", "Google Chrome";v="124.0.6367.91", "Not-A.Brand";v="99.0.0.0"',
    "Sec-Ch-Ua-Model": "",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
    "Priority": "u=0, i",
}

BLOCK_CODES = (403, 406, 429, 501, 503)


class HttpClient:
    def __init__(self, session, logger=None, auto_mutate=True, adaptive_throttle=True):
        # анти-петля
        self._req_history = []
        self._max_req_history = 60
        self.session = session
        self.logger = logger
        self.counter = 0
        self.live = True
        self.auto_mutate = auto_mutate
        self.adaptive_throttle = adaptive_throttle
        # === TLS impersonation через curl_cffi (Chrome 124 JA3+Akamai fingerprint) ===
        self._using_curl_cffi = False
        try:
            from curl_cffi import requests as _cc
            self.s = _cc.Session(impersonate="chrome124")
            self._using_curl_cffi = True
            if self.live:
                print("[http] TLS impersonation: curl_cffi chrome124", flush=True)
        except ImportError:
            # fallback на requests
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

    def _fallback_to_requests(self):
        """Переключиться на plain requests если curl_cffi TLS-хендшейк не проходит.
        Заголовки Chrome fingerprint остаются (они в _headers)."""
        if getattr(self, "_fallback_done", False):
            return
        self._fallback_done = True
        try:
            self.s.close()
        except Exception:
            pass
        import requests as _r
        self.s = _r.Session()
        retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[502, 503])
        self.s.mount("http://", HTTPAdapter(max_retries=retry))
        self.s.mount("https://", HTTPAdapter(max_retries=retry))
        if getattr(self.session, "proxy", None):
            self.s.proxies = {"http": self.session.proxy, "https": self.session.proxy}
        self.s.verify = False
        self._using_curl_cffi = False
        if self.live:
            print("[http] fallback: curl_cffi TLS blocked → plain requests", flush=True)

    def _headers(self, extra=None, sec_fetch=None):
        """Полный Chrome fingerprint + session overrides + sec-fetch."""
        # базовый набор от Chrome
        h = dict(CHROME_FINGERPRINT)
        # UA из сессии или случайный
        h["User-Agent"] = getattr(self.session, "user_agent", None) or random.choice(USER_AGENTS)
        # sec-fetch override (для CSS/JS/API-запросов)
        if sec_fetch:
            h.update(sec_fetch)
        # extra-настройки из --extra
        for x in getattr(self.session, "extra", []):
            if x.startswith("cookie="):
                h["Cookie"] = x[7:]
            elif x.startswith("header:"):
                kv = x[7:]
                if "=" in kv:
                    k, _, v = kv.partition("=")
                    h[k.strip()] = v.strip()
            elif x.startswith("no-fingerprint"):
                # урезанный набор — только UA (для тестов WAF)
                h = {"User-Agent": h["User-Agent"]}
        if extra:
            h.update(extra)
        return h

    def _human_delay(self, base=0.4, mean_extra=0.8):
        """Пауза по экспоненциальному распределению — как у человека."""
        return base + random.expovariate(1.0 / mean_extra)

    def warmup(self, origin):
        """
        Прогрев сессии: главная → robots.txt → CSS → favicon.
        Заставляет WAF видеть «нормальный браузер», а не сканер.
        """
        import time as _t
        origin = origin.rstrip("/")

        def _get(url, **kw):
            try:
                return self.get(url, **kw)
            except Exception:
                return None

        # 1. главная
        _get(origin + "/", headers=self._headers(sec_fetch={
            "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1",
        }))
        _t.sleep(self._human_delay())

        # 2. robots.txt — браузеры иногда дергают
        _get(origin + "/robots.txt", headers=self._headers(sec_fetch={
            "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Dest": "empty",
        }))
        _t.sleep(self._human_delay(base=0.2, mean_extra=0.4))

        # 3. favicon.ico — все браузеры автоматически
        _get(origin + "/favicon.ico", headers=self._headers(sec_fetch={
            "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Dest": "image",
        }))
        _t.sleep(self._human_delay(base=0.15, mean_extra=0.3))

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
        # анти-петля: 60 ИДЕНТИЧНЫХ запросов (method+url+data+params) подряд → abort
        # одинаковый URL с разным body — это НЕ петля, это работа модуля
        try:
            _sig = (method, url, repr(data)[:200], repr(params)[:200])
            self._req_history.append(_sig)
            if len(self._req_history) > self._max_req_history:
                self._req_history = self._req_history[-self._max_req_history:]
            if (len(self._req_history) == self._max_req_history
                    and len(set(self._req_history)) == 1):
                raise RuntimeError(f"[http] loop detected on {url} - aborting")
        except AttributeError:
            pass
        t0 = time.time()
        try:
            try:
                r = self.s.request(
                    method, url,
                    headers=self._headers(headers),
                    params=params, data=data, json=json,
                    timeout=self.session.timeout,
                    allow_redirects=allow_redirects,
                    stream=stream,
                )
            except Exception as _e:
                # curl_cffi TLS-хендшейк блокируется локальным прокси (Huawei/VPN) → fallback
                _err = str(_e).lower()
                if self._using_curl_cffi and any(k in _err for k in
                        ("ssl", "tls", "eof", "boringssl", "syscall", "connection closed")):
                    self._fallback_to_requests()
                    r = self.s.request(
                        method, url,
                        headers=self._headers(headers),
                        params=params, data=data, json=json,
                        timeout=self.session.timeout,
                        allow_redirects=allow_redirects,
                        stream=stream,
                    )
                else:
                    raise
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
