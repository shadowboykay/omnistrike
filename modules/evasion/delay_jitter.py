"""delay_jitter — random delays between requests (avoid rate-limit)"""
import time, random
from core.http import HttpClient

class DelayJitter:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        N = 20
        min_d, max_d = 0.3, 2.5
        print(f"[delay_jitter] {N} requests with {min_d}-{max_d}s jitter")
        codes = {}
        for i in range(N):
            r = http.get(session.target)
            code = r.status_code if r else None
            codes[code] = codes.get(code, 0) + 1
            d = random.uniform(min_d, max_d)
            if i < N-1: time.sleep(d)
        print(f"  codes: {codes}")
        return {"codes": codes}
