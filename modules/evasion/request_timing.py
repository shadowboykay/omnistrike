"""request_timing — measure server response timing, detect rate-limit thresholds"""
import time
from core.http import HttpClient

class RequestTiming:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        print("[request_timing] measuring response times")
        times = []
        for i in range(30):
            t0 = time.time()
            r = http.get(session.target)
            dt = time.time() - t0
            times.append(dt)
            if r and r.status_code in (429, 503):
                print(f"  [!] rate-limit hit at request {i+1}")
                logger.finding("rate_limit_hit","info",f"at request {i+1}")
                break
        if times:
            avg = sum(times)/len(times)
            mn, mx = min(times), max(times)
            print(f"  avg={avg*1000:.0f}ms min={mn*1000:.0f}ms max={mx*1000:.0f}ms")
            print(f"  total={len(times)} requests")
            logger.info("timing", avg_ms=round(avg*1000), min_ms=round(mn*1000), max_ms=round(mx*1000))
        return {"times": times, "avg": sum(times)/len(times) if times else 0}
