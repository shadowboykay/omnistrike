# core/probe.py — unified probe layer: baseline + inject + mutate + verify
import time
from core.http import HttpClient
from core.mutator import mutate


class Probe:
    """
    Unified vulnerability probe. Handles:
      - baseline comparison
      - payload injection
      - automatic mutation on block (403/406/429/503)
      - false-positive filter (reflected vs executed)
      - timing analysis (for blind/time-based)
    """

    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        self.http = HttpClient(session, logger)
        self.baseline = None
        self.stats = {"requests": 0, "blocks": 0, "hits": 0, "mutations": 0}

    def baseline_probe(self, url, method="GET", data=None):
        """Establish baseline response."""
        r = self.http.get(url) if method == "GET" else self.http.post(url, data=data)
        if not r:
            return None
        self.baseline = {
            "code": r.status_code,
            "len": len(r.content),
            "text": r.text,
            "time": 0,
        }
        return self.baseline

    def inject(self, url_fn, payload, method="GET", data_fn=None,
               detect_markers=None, expect_code=None, allow_redirects=True):
        """
        Inject payload, compare with baseline, mutate on block.
        url_fn(payload) -> URL with payload
        data_fn(payload) -> POST data (if method=POST)
        detect_markers: list of strings that signal hit
        expect_code: what code signals success (default 200)
        Returns: {"hit": bool, "reason": str, "payload": str, "variants_tried": int}
        """
        expect_code = expect_code or 200
        variants = mutate(payload, n=5, base_first=True)
        variants_tried = 0

        for variant in variants:
            variants_tried += 1
            self.stats["requests"] += 1

            t0 = time.time()
            if method == "GET":
                r = self.http.get(url_fn(variant), allow_redirects=allow_redirects)
            else:
                r = self.http.post(url_fn(variant), data=data_fn(variant) if data_fn else None,
                                   allow_redirects=allow_redirects)
            dt = time.time() - t0

            if not r:
                continue

            # blocked? mutate and retry
            if r.status_code in (403, 406, 429, 503):
                self.stats["blocks"] += 1
                self.stats["mutations"] += 1
                continue

            # not expected code? skip
            if r.status_code != expect_code:
                continue

            # false-positive filter: payload reflected as text
            if variant in r.text and "<script" in variant.lower():
                # it's echoed — check if it was executed (not HTML-encoded)
                if "&lt;script" in r.text or "&lt;" in r.text[:100]:
                    return {"hit": False, "reason": "reflected-encoded",
                            "payload": variant, "variants_tried": variants_tried}
                # raw reflection = XSS
                return {"hit": True, "reason": "raw-reflected",
                        "payload": variant, "variants_tried": variants_tried}

            # marker match
            if detect_markers:
                low = r.text.lower()
                for m in detect_markers:
                    if m.lower() in low:
                        self.stats["hits"] += 1
                        return {"hit": True, "reason": f"marker:{m}",
                                "payload": variant, "variants_tried": variants_tried,
                                "code": r.status_code}

            # length diff (blind boolean)
            if self.baseline and abs(len(r.content) - self.baseline["len"]) > 200:
                return {"hit": True, "reason": f"len-diff:{len(r.content) - self.baseline['len']}",
                        "payload": variant, "variants_tried": variants_tried,
                        "code": r.status_code}

        return {"hit": False, "reason": "no-hit", "payload": payload,
                "variants_tried": variants_tried}

    def time_probe(self, url_fn, payload, delay_threshold=2.5):
        """Test time-based injection (SLEEP, WAITFOR)."""
        self.stats["requests"] += 1
        t0 = time.time()
        r = self.http.get(url_fn(payload))
        dt = time.time() - t0
        if r and dt > delay_threshold:
            self.stats["hits"] += 1
            return {"hit": True, "delay": round(dt, 2), "payload": payload}
        return {"hit": False, "delay": round(dt, 2)}

    def summary(self):
        return dict(self.stats)
