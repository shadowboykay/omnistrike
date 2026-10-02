"""race_condition v2 — parallel race detection with baseline + verify.

Классические TOCTOU-уязвимости:
  - купоны / промокоды (один код → много активаций)
  - переводы баланса (double-spend)
  - лайки / голоса (multi-count)
  - claim / redeem / withdraw
  - rate-limit bypass (N успешных где должен быть 1)

Сигналы:
  1. multiple_successes: N×200 когда baseline ожидал бы 1
  2. distinct_bodies: разные тела ответов при идентичных запросах (TOCTOU)
  3. baseline_rejected: baseline 4xx/302, а параллель — 200 (bypass)
  4. timing_window: все успехи < 100ms друг от друга (real race)

WAF-защита: если ловим 429, залп разбивается на батчи с jitter.
"""
import time
import threading
import hashlib
from collections import Counter
from core.http import HttpClient
from core.verify import confidence, is_signal
from core.waf_bypass import is_blocked


# типовые race-endpoints
RACE_PATHS = [
    "/api/coupon", "/api/redeem", "/api/claim", "/api/vote", "/api/like",
    "/api/transfer", "/api/withdraw", "/api/deposit", "/api/buy",
    "/api/purchase", "/api/checkout", "/api/cart", "/api/order",
    "/api/referral", "/api/invite", "/api/bonus", "/api/discount",
    "/api/subscribe", "/api/register", "/api/signup", "/api/apply",
]


class RaceCondition:
    def __init__(self, parallel=20, timeout=10, batch_size=5, jitter=0.05):
        self.parallel = parallel
        self.timeout = timeout
        self.batch_size = batch_size   # если 429 — бьём на батчи
        self.jitter = jitter

    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        # POST-поля из --extra post=...
        post_data = {}
        for x in getattr(session, "extra", []) or []:
            if x.startswith("post="):
                for pair in x[5:].split("&"):
                    k, _, v = pair.partition("=")
                    post_data[k] = v

        if not post_data:
            print("[race v2] warning: --extra post=key=value not provided")
            print("[race v2] using default POST body: {action: claim, amount: 1}")

        findings = []

        # базовый URL — либо target, либо target + RACE_PATHS
        candidates = [target]
        base = target.rstrip("/")
        for path in RACE_PATHS:
            candidates.append(base + path)

        for endpoint in candidates:
            # === 1. baseline: один запрос ===
            try:
                base_r = self._one(http, endpoint, post_data)
            except Exception:
                continue
            if not base_r:
                continue

            baseline_status = base_r["status"]
            baseline_len = base_r["len"]
            baseline_time = base_r["time"]

            # если endpoint вообще недоступен — пропускаем
            if baseline_status == 404:
                continue
            # если WAF блокирует даже baseline — запоминаем, но пробуем
            if is_blocked_type(baseline_status):
                print(f"[race v2] {endpoint}: baseline blocked ({baseline_status})")
                continue

            print(f"[race v2] {endpoint} baseline={baseline_status} {baseline_len}b {baseline_time:.2f}s")

            # === 2. параллельный залп ===
            burst = self._burst(http, endpoint, post_data)
            if not burst:
                continue

            statuses = Counter(r["status"] for r in burst)
            successes_200 = [r for r in burst if 200 <= r["status"] < 300]
            success_count = len(successes_200)

            print(f"[race v2] burst: {len(burst)} requests, statuses={dict(statuses)}")

            # если WAF режет — пробуем батчами
            if statuses.get(429, 0) > len(burst) / 2:
                print(f"[race v2] 429 detected — retrying in batches with jitter")
                burst = self._burst_batched(http, endpoint, post_data)
                statuses = Counter(r["status"] for r in burst)
                successes_200 = [r for r in burst if 200 <= r["status"] < 300]
                success_count = len(successes_200)
                print(f"[race v2] batched burst: statuses={dict(statuses)}")

            # === 3. анализ сигналов ===
            signal = None
            strength = 0.0
            evidence = {}

            # сигнал A: несколько 200 когда ожидали один
            if success_count > 1:
                # сколько уникальных тел среди успехов?
                hashes = [hashlib.md5(str(r["body_hash"]).encode()).hexdigest()[:8]
                          for r in successes_200]
                distinct_hashes = len(set(hashes))

                if distinct_hashes > 1:
                    signal = "race_toctou"
                    strength = 0.9
                    evidence = {
                        "successes": success_count,
                        "distinct_responses": distinct_hashes,
                        "hashes": list(set(hashes))[:5],
                    }
                else:
                    # одинаковые 200 — может быть rate-limit bypass или idempotent endpoint
                    # проверим таймингом: race обычно все успехи в узком окне
                    times = [r["time"] for r in successes_200]
                    if times:
                        time_span = max(times) - min(times)
                        if time_span < 0.2:
                            signal = "race_parallel_success"
                            strength = 0.7
                            evidence = {
                                "successes": success_count,
                                "time_span": round(time_span, 3),
                            }
                        else:
                            # разброс большой — это не race, это serialised requests
                            signal = "possible_ratelimit_bypass"
                            strength = 0.5
                            evidence = {
                                "successes": success_count,
                                "time_span": round(time_span, 3),
                            }

            # сигнал B: baseline был 4xx/302, а параллель — 200
            if not signal and baseline_status not in range(200, 300):
                if success_count >= 2:
                    signal = "race_auth_bypass"
                    strength = 0.85
                    evidence = {
                        "baseline_status": baseline_status,
                        "successes": success_count,
                    }

            if not signal:
                continue

            # === 4. verify: повторить залп ×2 ===
            verify_ok, verify_ratio = self._verify(http, endpoint, post_data, signal)
            if not verify_ok:
                print(f"[race v2] {endpoint}: verify failed ({verify_ratio:.2f})")
                continue

            # === 5. confidence + is_signal ===
            conf = confidence(strength, verify_ratio)
            if not is_signal(conf, floor=0.55, module="race_condition"):
                continue

            sev = "critical" if signal in ("race_toctou", "race_auth_bypass") else "high"

            findings.append({
                "endpoint": endpoint,
                "signal": signal,
                "severity": sev,
                "evidence": evidence,
                "verify_ratio": verify_ratio,
                "confidence": conf,
            })
            print(f"  ✓ {signal}: {endpoint} conf={int(conf*100)} evidence={evidence}")
            logger.finding(f"race_{signal}", sev,
                           f"{endpoint} conf={int(conf*100)} evidence={evidence}")

        print(f"[race v2] findings: {len(findings)}")
        return {"findings": findings}

    # ============== helpers ==============

    def _one(self, http, url, data):
        """Один POST, возвращает dict {status, len, time, body_hash}."""
        t0 = time.time()
        try:
            r = http.post(url, data=data or {"action": "claim", "amount": "1"})
        except Exception:
            return None
        dt = time.time() - t0
        if not r:
            return None
        return {
            "status": r.status_code,
            "len": len(r.content),
            "time": dt,
            "body_hash": hash(r.text[:500]),
        }

    def _burst(self, http, url, data):
        """N параллельных POST, синхронизированных по Event."""
        results = []
        lock = threading.Lock()
        start_event = threading.Event()
        data = data or {"action": "claim", "amount": "1"}

        def _fire():
            start_event.wait()
            t0 = time.time()
            try:
                r = http.post(url, data=dict(data))
            except Exception:
                r = None
            dt = time.time() - t0
            if r:
                with lock:
                    results.append({
                        "status": r.status_code,
                        "len": len(r.content),
                        "time": dt,
                        "body_hash": hash(r.text[:500]),
                    })

        threads = [threading.Thread(target=_fire) for _ in range(self.parallel)]
        for t in threads:
            t.start()
        # синхронизация: все ждут события
        time.sleep(0.05)
        start_event.set()
        for t in threads:
            t.join(timeout=self.timeout)
        return results

    def _burst_batched(self, http, url, data):
        """Если WAF ловит на 429 — разбиваем на батчи с jitter."""
        results = []
        for _ in range(0, self.parallel, self.batch_size):
            batch = self._burst_partial(http, url, data, self.batch_size)
            results.extend(batch)
            time.sleep(self.jitter + 0.05)
        return results

    def _burst_partial(self, http, url, data, n):
        results = []
        lock = threading.Lock()
        start_event = threading.Event()
        data = data or {"action": "claim", "amount": "1"}

        def _fire():
            start_event.wait()
            t0 = time.time()
            try:
                r = http.post(url, data=dict(data))
            except Exception:
                r = None
            dt = time.time() - t0
            if r:
                with lock:
                    results.append({
                        "status": r.status_code,
                        "len": len(r.content),
                        "time": dt,
                        "body_hash": hash(r.text[:500]),
                    })

        threads = [threading.Thread(target=_fire) for _ in range(n)]
        for t in threads:
            t.start()
        time.sleep(0.03)
        start_event.set()
        for t in threads:
            t.join(timeout=self.timeout)
        return results

    def _verify(self, http, url, data, signal):
        """Повторить залп ×2, вернуть (verified, ratio)."""
        matches = 0
        for _ in range(2):
            burst = self._burst(http, url, data)
            successes = [r for r in burst if 200 <= r["status"] < 300]
            if signal in ("race_toctou", "race_parallel_success"):
                if len(successes) > 1:
                    matches += 1
            elif signal == "race_auth_bypass":
                if len(successes) >= 2:
                    matches += 1
            elif signal == "possible_ratelimit_bypass":
                if len(successes) > 1:
                    matches += 1
        return matches >= 1, matches / 2


def is_blocked_type(status):
    """Проверка что статус похож на WAF-блок."""
    return status in (403, 406, 429, 501, 502, 503)
