# core/sniper.py — sniper layer: targeted probe + verify + evidence + confidence
import time
import re
from core.http import HttpClient
from core.payload_source import get_payloads


class SniperProbe:
    """
    Sniper probe. Отличия от обычного Probe:
      - Baseline запоминает response (body, code, len, time, headers hash)
      - Payload передаётся ОДИН целевой (не список)
      - Hit требует подтверждения (2 из 3 проверок)
      - Evidence — точный фрагмент ответа доказывающий находку
      - Confidence — score 0-100
    """

    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        self.http = HttpClient(session, logger)
        self.baseline = None
        self.stats = {"requests": 0, "hits": 0, "verified": 0, "fp_filtered": 0}

    # ---------- baseline ----------

    def take_baseline(self, url, method="GET", data=None, samples=3):
        """Take multiple baseline samples for stability analysis."""
        samples_data = []
        for _ in range(samples):
            t0 = time.time()
            r = self.http.get(url) if method == "GET" else self.http.post(url, data=data)
            dt = time.time() - t0
            if r:
                samples_data.append({
                    "code": r.status_code,
                    "len": len(r.content),
                    "time": dt,
                    "hash": hash(r.text[:1000]),
                })
            time.sleep(0.15)

        if not samples_data:
            self.baseline = None
            return None

        self.baseline = {
            "code": samples_data[0]["code"],
            "len": samples_data[0]["len"],
            "avg_time": sum(s["time"] for s in samples_data) / len(samples_data),
            "stable_len": len(set(s["len"] for s in samples_data)) == 1,
            "stable_hash": len(set(s["hash"] for s in samples_data)) == 1,
            "samples": samples_data,
        }
        return self.baseline

    # ---------- probe ----------

    def probe(self, url_fn, payload, method="GET", data_fn=None,
              detect_markers=None, verify_count=2, label=None):
        """
        Single targeted probe with verification.
        Returns:
          {hit, verified, reason, evidence, confidence, code, response_snippet}
        """
        self.stats["requests"] += 1
        t0 = time.time()
        if method == "GET":
            r = self.http.get(url_fn(payload))
        else:
            r = self.http.post(url_fn(payload), data=data_fn(payload) if data_fn else None)
        dt = time.time() - t0

        if not r:
            return {"hit": False, "reason": "no_response", "confidence": 0}

        # === detection ===
        hit = False
        reason = ""
        evidence = ""
        confidence = 0

        # 1. marker match
        if detect_markers:
            low = r.text.lower()
            for m in detect_markers:
                if m.lower() in low:
                    hit = True
                    reason = f"marker:{m}"
                    idx = low.find(m.lower())
                    evidence = r.text[max(0, idx - 30):idx + len(m) + 30]
                    confidence = 70
                    break

        # 2. raw reflection (XSS)
        if not hit and payload in r.text:
            # check if encoded
            if "&lt;" in r.text[:500] or "&#x3c;" in r.text[:500].lower():
                self.stats["fp_filtered"] += 1
                return {"hit": False, "reason": "reflected_encoded", "confidence": 0}
            hit = True
            reason = "raw_reflection"
            idx = r.text.find(payload)
            evidence = r.text[max(0, idx - 20):idx + len(payload) + 20]
            confidence = 75

        # 3. length diff (blind boolean)
        if not hit and self.baseline:
            diff = abs(len(r.content) - self.baseline["len"])
            if diff > 200:
                hit = True
                reason = f"length_diff:{diff}"
                evidence = f"baseline={self.baseline['len']}b, now={len(r.content)}b"
                confidence = 50

        # 4. time-based (blind time)
        if not hit and self.baseline:
            time_diff = dt - self.baseline["avg_time"]
            if time_diff > 2.5:
                hit = True
                reason = f"time_delay:{time_diff:.1f}s"
                evidence = f"baseline={self.baseline['avg_time']:.2f}s, now={dt:.2f}s"
                confidence = 65

        if not hit:
            return {"hit": False, "reason": "no_hit", "confidence": 0}

        self.stats["hits"] += 1

        # === verify ===
        if verify_count > 0:
            confirmed = self._verify(url_fn, payload, method, data_fn,
                                     detect_markers, reason, verify_count)
            if confirmed:
                self.stats["verified"] += 1
                confidence = min(confidence + 20, 95)
            else:
                confidence -= 30  # weak evidence

        return {
            "hit": True,
            "verified": confidence >= 70,
            "reason": reason,
            "evidence": evidence,
            "confidence": confidence,
            "code": r.status_code,
            "response_snippet": r.text[:300],
            "response_obj": r,
        }

    def _verify(self, url_fn, payload, method, data_fn, markers, orig_reason, times):
        """Independent confirmation — different approach than original."""
        confirms = 0
        for _ in range(times):
            time.sleep(0.2)
            try:
                # different variant
                mutated = payload + (" " if " " in payload else "/*x*/")
                if method == "GET":
                    r = self.http.get(url_fn(mutated))
                else:
                    r = self.http.post(url_fn(mutated), data=data_fn(mutated) if data_fn else None)
                if not r:
                    continue

                if markers and any(m.lower() in r.text.lower() for m in markers):
                    confirms += 1
                elif "reflection" in orig_reason and payload in r.text:
                    confirms += 1
                elif "length_diff" in orig_reason and self.baseline:
                    if abs(len(r.content) - self.baseline["len"]) > 200:
                        confirms += 1
                elif "time_delay" in orig_reason:
                    # re-check timing
                    t0 = time.time()
                    if method == "GET":
                        self.http.get(url_fn(payload))
                    else:
                        self.http.post(url_fn(payload), data=data_fn(payload) if data_fn else None)
                    if time.time() - t0 > 2.5:
                        confirms += 1
            except Exception:
                pass

        return confirms >= 1

    def summary(self):
        return dict(self.stats)
