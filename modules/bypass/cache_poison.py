"""cache_poison — web cache poisoning probe (unkeyed headers)"""
from core.http import HttpClient
import time, random

class CachePoison:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        marker = f"omni{random.randint(1000,9999)}"
        findings = []

        # unkeyed header probes
        probes = [
            {"X-Forwarded-Host": marker + ".evil.example"},
            {"X-Forwarded-Scheme": "http"},
            {"X-Original-URL": "/" + marker},
            {"X-Rewrite-URL": "/" + marker},
            {"X-Host": marker + ".evil.example"},
            {"X-Forwarded-Server": marker + ".evil.example"},
            {"X-HTTP-Method-Override": "POST"},
        ]
        for h in probes:
            r1 = http.get(target, headers=h)
            if not r1: continue
            # check if marker reflected in response or affects redirects
            if marker in r1.text or marker in r1.headers.get("Location",""):
                print(f"  [!] reflected: {h} -> marker in response")
                logger.finding("cache_poison_reflect","high",str(h))
                findings.append({"header":h,"type":"reflect"})
            # cache hit test
            cache_status = r1.headers.get("X-Cache") or r1.headers.get("CF-Cache-Status")
            if cache_status and "hit" in cache_status.lower():
                findings.append({"header":h,"type":"cached","status":cache_status})
                logger.finding("cache_poison_hit","high",f"{h} cached={cache_status}")

            # check if response cached under our probe
            time.sleep(0.3)
            r2 = http.get(target)  # baseline
            if r2 and marker in r2.text:
                findings.append({"header":h,"type":"poisoned_cache"})
                print(f"  [!] POISONED: marker in baseline after probe")
                logger.finding("cache_poisoned","critical",str(h))

        print(f"[cache_poison] {len(findings)} findings")
        return {"findings": findings}
