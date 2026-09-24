"""swarm_mode — parallel multi-strategy attack"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient
from core.session import Session
import time


STRATEGIES = {
    "fast":      {"delay": 0.1, "ua": "Mozilla/5.0 Chrome/120", "desc": "быстрый"},
    "slow":      {"delay": 5.0, "ua": "Mozilla/5.0 Firefox/121", "desc": "тихий"},
    "googlebot": {"delay": 2.0, "ua": "Googlebot/2.1", "desc": "под Googlebot"},
    "mobile":    {"delay": 1.5, "ua": "Mozilla/5.0 iPhone Safari", "desc": "мобильный"},
    "seo_bot":   {"delay": 0.5, "ua": "SemrushBot/7~bl", "desc": "SEO-бот"},
}


class SwarmMode:
    def run(self, session, logger):
        target = session.target
        print(f"[swarm] target: {target}")
        print(f"[swarm] launching {len(STRATEGIES)} strategies in parallel")
        print()

        def run_strategy(name, cfg):
            sub = Session(target=target, timeout=15)
            sub.user_agent = cfg["ua"]
            h = HttpClient(sub, None)
            time.sleep(cfg["delay"])
            t0 = time.time()
            r = h.get(target)
            dt = time.time() - t0
            return {
                "strategy": name, "desc": cfg["desc"],
                "code": r.status_code if r else None,
                "size": len(r.content) if r else 0,
                "time": round(dt, 2), "delay_applied": cfg["delay"],
            }

        results = []
        with ThreadPoolExecutor(max_workers=len(STRATEGIES)) as ex:
            futs = {ex.submit(run_strategy, n, c): n for n, c in STRATEGIES.items()}
            for f in as_completed(futs):
                r = f.result()
                results.append(r)
                print(f"  + {r['strategy']:12s} {r['code']} {r['size']}b delay={r['delay_applied']}s time={r['time']}s")

        codes = set(r["code"] for r in results if r["code"])
        sizes = set(r["size"] for r in results if r["size"])
        print()
        print(f"[swarm] codes: {codes}")
        print(f"[swarm] unique sizes: {len(sizes)}")
        if len(sizes) > 1:
            print("  ! different responses")
            logger.finding("swarm_anomaly", "medium", f"{len(sizes)} sizes")
        if 403 in codes or 429 in codes:
            print("  ! some blocked")
            logger.finding("swarm_block", "info", "some blocked")
        logger.finding("swarm_done", "info", f"{len(results)} strategies")
        return {"results": results}
