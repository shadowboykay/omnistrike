"""chameleon_v2 — behavioral analysis: headers + timing + stability + probes"""
from core.chameleon_v2 import ChameleonV2


class ChameleonV2Module:
    def run(self, session, logger):
        c = ChameleonV2(session, logger)
        result = c.run_analysis()
        if not result:
            return {}
        print()
        print(f"[chameleon_v2] classification: {result['verdict']}")
        if result["verdict"] == "honeypot":
            print("[chameleon_v2] ⚠ ABORT — behavioral honeypot detected")
        return result
