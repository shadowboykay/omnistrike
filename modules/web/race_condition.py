"""race_condition — TOCTOU probe via parallel requests (coupon/redeem/transfer)"""
from concurrent.futures import ThreadPoolExecutor
from core.http import HttpClient

RACE_PATHS = ["/api/coupon","/api/redeem","/api/transfer","/api/withdraw","/api/vote",
              "/api/claim","/api/buy","/api/purchase","/api/checkout","/api/referral",
              "/api/invite","/api/bonus","/api/discount"]

class RaceCondition:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        findings = []

        for path in RACE_PATHS:
            url = base + path
            probe = http.get(url)
            if not probe or probe.status_code == 404: continue
            print(f"[race] probing {path} ({probe.status_code})")

            # send N parallel
            N = 20
            payload = {"action":"claim","amount":"1"}
            def hit(_):
                return http.post(url, json=payload)
            with ThreadPoolExecutor(max_workers=N) as ex:
                results = list(ex.map(hit, range(N)))
            codes = {}
            for r in results:
                if r: codes[r.status_code] = codes.get(r.status_code, 0) + 1
            success = codes.get(200, 0) + codes.get(201, 0)
            if success > 1:
                findings.append({"path":path,"successes":success,"total":N})
                print(f"  [!] {success}/{N} succeeded — possible race")
                logger.finding("race_condition","high",f"{path} {success}/{N} parallel success")

        print(f"[race_condition] {len(findings)}")
        return {"findings": findings}
