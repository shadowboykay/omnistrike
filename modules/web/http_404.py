"""http_404 — custom 404 page detection + injected-path analysis"""
from core.http import HttpClient

class Http404:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        import random
        probes = [f"/omni-nonexistent-{random.randint(10000,99999)}" for _ in range(5)]
        codes = {}
        bodies = []
        for p in probes:
            r = http.get(base + p)
            if r:
                codes[r.status_code] = codes.get(r.status_code, 0) + 1
                bodies.append(len(r.content))
        print(f"[404] codes={codes} body_sizes={bodies}")
        # custom 404 page
        if codes.get(200, 0) > 0:
            logger.finding("soft_404", "info", "200 on nonexistent paths -> soft 404")
            print("  [!] soft 404 detected")
        elif len(set(bodies)) == 1 and 404 in codes:
            logger.finding("custom_404", "info", f"custom 404 page, size={bodies[0]}")
        return {"codes": codes, "body_sizes": bodies}
