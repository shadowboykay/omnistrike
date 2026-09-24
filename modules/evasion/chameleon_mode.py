"""chameleon_mode — detect target type, adapt attack strategy"""
from core.chameleon import Chameleon


class ChameleonMode:
    def run(self, session, logger):
        ch = Chameleon(session, logger)
        detected = ch.detect()
        summary = ch.summary()

        print()
        print(f"[chameleon] detected: {detected.get('type')}")
        if detected.get("name"):
            print(f"[chameleon] name: {detected['name']}")
        print(f"[chameleon] strategy: {summary['message']}")
        print()

        if not ch.should_attack():
            print("[chameleon] ⚠ ABORT — honeypot detected, not attacking")
            logger.finding("chameleon_abort", "critical", "Honeypot detected")
            return summary

        # test delay
        print("[chameleon] testing delay policy...")
        import time
        t0 = time.time()
        ch.apply_delay()
        dt = time.time() - t0
        print(f"  delay: {dt:.2f}s")

        # verify attack works with delay
        from core.http import HttpClient
        h = HttpClient(session, logger)
        r = h.get(session.target)
        if r:
            print(f"  target still reachable: {r.status_code}")
            logger.finding("chameleon_ok", "info",
                           f"{detected.get('type')} strategy active")

        return summary
