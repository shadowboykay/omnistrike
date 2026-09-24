"""idor — insecure direct object reference probe (numeric/UUID ID sweep)"""
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient

class Idor:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        # baseline
        base = http.get(target)
        if not base: return {}
        base_len = len(base.content)
        base_status = base.status_code

        # find numeric/UUID ids in URL path or query
        ids = re.findall(r'(?<=/)(\d{1,6})(?=/|\?|$)', target)
        ids += re.findall(r'[?&](?:id|user|uid|account|pid)=(\d{1,6})', target)
        uuids = re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', target)

        if not ids and not uuids:
            print("[idor] no numeric/UUID IDs in URL"); return {"findings": []}

        findings = []

        def probe(val, kind, pos):
            new_url = target[:pos[0]] + str(val) + target[pos[1]:]
            r = http.get(new_url)
            if not r: return None
            if r.status_code == 200 and abs(len(r.content) - base_len) > 100:
                return {"id":val,"kind":kind,"len_diff":abs(len(r.content)-base_len)}
            return None

        for old_id in ids:
            pos = target.find(old_id)
            candidates = []
            n = int(old_id)
            for off in [-2,-1,1,2,10,100,1000,-1000]:
                v = n + off
                if v > 0: candidates.append(v)
            for c in candidates[:8]:
                res = probe(c, "numeric", (pos, pos+len(old_id)))
                if res:
                    findings.append(res)
                    print(f"  [+] id {old_id} -> {c} (diff {res['len_diff']}b)")
                    logger.finding("idor","high",f"id {old_id} -> {c}")

        print(f"[idor] {len(findings)} possible IDORs")
        return {"findings": findings}
