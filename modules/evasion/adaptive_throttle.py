"""adaptive_throttle — adaptive rate control (back off on 429/503, slow down)"""
import time, random
from core.http import HttpClient

class AdaptiveThrottle:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        delay = 0.2
        min_delay, max_delay = 0.1, 10.0
        hits = 0
        total = 0

        print(f"[adaptive_throttle] probing {session.target}")
        print(f"  start delay: {delay}s")

        for i in range(50):
            total += 1
            t0 = time.time()
            r = http.get(session.target)
            dt = time.time() - t0

            if r and r.status_code in (429, 503):
                delay = min(delay * 2, max_delay)
                hits += 1
                print(f"  [{i}] {r.status_code} — backing off to {delay:.2f}s")
                logger.info("throttle_backoff", delay=delay, code=r.status_code)
            elif r and r.status_code == 200:
                delay = max(delay * 0.95, min_delay)

            time.sleep(delay + random.uniform(0, delay*0.3))

        print(f"[adaptive_throttle] {total} requests, {hits} throttle hits, final delay {delay:.2f}s")
        logger.finding("adaptive_throttle","info",f"{hits} hits, delay={delay:.2f}s")
        return {"total": total, "hits": hits, "final_delay": delay}
