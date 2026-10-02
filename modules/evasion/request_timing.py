"""request_timing v2 — rate-limit detection + adaptive pacing.

Что определяет:
  1. baseline latency — средняя задержка на "чистом" соединении
  2. rate_limit_hit_at — на каком запросе сработал 429/503
  3. throttle curve — как меняется latency при нагрузке
  4. burst tolerance — сколько запросов подряд можно без блокировки
  5. recommended_delay — безопасная пауза для дальнейшего скана

Паттерны:
  - Cloudflare: 429 после N запросов в окне
  - Akamai: 503 после burst
  - Nginx limit_req: постепенный рост latency, потом 503
  - AWS WAF: 403 с X-Amzn-Waf-Action
"""
import time
import statistics
from collections import Counter
from core.http import HttpClient


BLOCK_CODES = (403, 406, 429, 500, 502, 503, 504)


class RequestTiming:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        N = 30
        mode = "quick"
        for x in getattr(session, "extra", []) or []:
            if x.startswith("timing_probe="):
                try:
                    N = int(x[13:])
                except Exception:
                    pass
            elif x.startswith("timing_mode="):
                mode = x[11:].strip()

        pauses = {"quick": 0.0, "aggressive": 0.05, "careful": 1.0}
        pause = pauses.get(mode, 0.0)

        print(f"[request_timing v2] target: {target}")
        print(f"[request_timing v2] probing {N} requests (mode={mode}, pause={pause}s)")

        times = []
        codes = []
        rate_limit_at = None
        first_429_headers = None

        for i in range(N):
            t0 = time.time()
            try:
                r = http.get(target)
            except Exception:
                times.append(0)
                codes.append(0)
                continue
            dt = time.time() - t0
            times.append(dt)

            code = r.status_code if r else 0
            codes.append(code)

            if code in BLOCK_CODES and rate_limit_at is None:
                rate_limit_at = i + 1
                first_429_headers = dict(r.headers) if r else {}
                print(f"  ! rate-limit hit at request #{i+1}: {code}")

            if (i + 1) % 5 == 0:
                marker = "!" if code in BLOCK_CODES else " "
                print(f"  #{i+1:3d}  {code}  {dt*1000:.0f}ms {marker}")

            if pause > 0 and i < N - 1:
                time.sleep(pause)

        valid_times = [t for t in times if t > 0]
        if not valid_times:
            print("[request_timing v2] no valid responses")
            return {"times": [], "avg": 0, "findings": []}

        avg = statistics.mean(valid_times)
        mn = min(valid_times)
        mx = max(valid_times)
        med = statistics.median(valid_times)
        stdev = statistics.stdev(valid_times) if len(valid_times) > 1 else 0

        first_third = valid_times[:len(valid_times)//3]
        last_third = valid_times[-len(valid_times)//3:]
        curve_growth = (statistics.mean(last_third) - statistics.mean(first_third)) if first_third and last_third else 0

        rl_pattern = "none"
        if rate_limit_at:
            ratio = rate_limit_at / N
            if ratio < 0.2:
                rl_pattern = "aggressive"
            elif ratio < 0.5:
                rl_pattern = "moderate"
            else:
                rl_pattern = "lenient"
        elif curve_growth > 0.5:
            rl_pattern = "soft-throttle"

        if rate_limit_at:
            elapsed = sum(times[:rate_limit_at])
            recommended = max(1.0, elapsed * 1.5 / rate_limit_at)
        elif curve_growth > 0.5:
            recommended = max(1.0, avg * 2)
        else:
            recommended = max(0.2, avg * 1.5)

        print()
        print(f"[request_timing v2] === analysis ===")
        print(f"  avg:  {avg*1000:.0f}ms")
        print(f"  med:  {med*1000:.0f}ms")
        print(f"  min:  {mn*1000:.0f}ms")
        print(f"  max:  {mx*1000:.0f}ms")
        print(f"  stdev: {stdev*1000:.0f}ms")
        print(f"  curve growth: {curve_growth*1000:+.0f}ms")
        print(f"  rate-limit: {rl_pattern}")
        if rate_limit_at:
            print(f"  hit at: request #{rate_limit_at}/{N}")
        print(f"  recommended delay: {recommended:.2f}s")

        code_counts = Counter(codes)
        print(f"  codes: {dict(code_counts)}")

        findings = []
        if rate_limit_at:
            findings.append({
                "type": "rate_limit_detected",
                "severity": "info",
                "hit_at": rate_limit_at,
                "pattern": rl_pattern,
                "recommended_delay": recommended,
                "headers": first_429_headers,
            })
            logger.finding("rate_limit", "info",
                           f"hit at #{rate_limit_at}, pattern={rl_pattern}")

        logger.info("request_timing",
                    avg_ms=round(avg*1000),
                    med_ms=round(med*1000),
                    stdev_ms=round(stdev*1000),
                    rate_limit=rl_pattern,
                    recommended_delay=round(recommended, 2))

        return {
            "times": times,
            "codes": codes,
            "avg": avg,
            "med": med,
            "min": mn,
            "max": mx,
            "stdev": stdev,
            "curve_growth": curve_growth,
            "rate_limit_at": rate_limit_at,
            "rate_limit_pattern": rl_pattern,
            "recommended_delay": recommended,
            "findings": findings,
        }
