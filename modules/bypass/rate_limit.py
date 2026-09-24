"""rate_limit — measure rate limiting + bypass via header rotation"""
from concurrent.futures import ThreadPoolExecutor
from core.http import HttpClient
import time

class RateLimit:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        N = 50
        print(f"[rate_limit] sending {N} parallel requests")

        def hit(_):
            return http.get(target)

        t0 = time.time()
        with ThreadPoolExecutor(max_workers=20) as ex:
            results = list(ex.map(hit, range(N)))
        dt = time.time() - t0

        codes = {}
        for r in results:
            if r: codes[r.status_code] = codes.get(r.status_code, 0) + 1
        print(f"  {N} req in {dt:.2f}s -> {codes}")

        throttled = any(c in codes for c in (429, 503, 403))
        if throttled:
            logger.finding("rate_limit","info",f"throttling detected: {codes}")
        # bypass attempt
        if throttled:
            bypass = []
            for h in ["X-Forwarded-For","X-Real-IP","X-Originating-IP"]:
                import random
                ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                r = http.get(target, headers={h: ip})
                if r and r.status_code == 200:
                    bypass.append({h: ip, "code": 200})
                    logger.finding("rate_limit_bypass","high",f"{h}: {ip}")
            return {"throttled": True, "codes": codes, "bypass": bypass}
        return {"throttled": False, "codes": codes, "rps": round(N/dt,2)}
