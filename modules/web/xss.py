"""xss — reflected XSS scanner with baseline, mutation, FP-filter (v2)"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.probe import Probe
from core.payload_source import get_payloads, detect_waf

MARKER = "omni7x9z"


class Xss:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"q": ["test"]}

        probe = Probe(session, logger)
        base = probe.baseline_probe(target)
        if not base:
            print("[xss] no baseline — target unreachable")
            return {"findings": []}
        print(f"[xss] baseline: {base['code']} {base['len']}b")

        payloads = get_payloads("html_body", waf=detect_waf(session), limit=150)
        print(f"[xss] {len(payloads)} payloads on params {list(params.keys())}")

        findings = []

        for name in params:
            print(f"\n[xss] param '{name}'")
            for i, p in enumerate(payloads, 1):
                # inject marker for tracking
                test = p.replace("alert(1)", f'alert("{MARKER}")')
                url_fn = lambda pl, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()}, name: pl}, doseq=True))
                )
                r = probe.inject(url_fn, test, detect_markers=[MARKER])
                if r["hit"]:
                    print(f"  ✓ {r['reason']} — {test[:60]}")
                    findings.append({
                        "param": name,
                        "payload": test,
                        "type": r["reason"],
                        "severity": "high" if "raw" in r["reason"] else "medium",
                    })
                    logger.finding("xss", "high" if "raw" in r["reason"] else "medium",
                                   f"{name}={test[:60]} ({r['reason']})")
                elif i % 30 == 0:
                    print(f"  · {i}/{len(payloads)} done, {len(findings)} hits so far")

        stats = probe.summary()
        print(f"\n[xss] total findings: {len(findings)}")
        print(f"[xss] stats: req={stats['requests']} blocks={stats['blocks']} mutations={stats['mutations']}")

        return {"findings": findings, "stats": stats}
