"""csti_injection — Client-Side Template Injection (Angular/Vue/React)"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.probe import Probe
from core.payload_source import get_payloads

PAYLOADS = get_payloads("csti")


class CstiInjection:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"q": ["test"]}

        probe = Probe(session, logger)
        base = probe.baseline_probe(target)
        if not base:
            print("[csti] no baseline"); return {"findings": []}
        print(f"[csti] baseline: {base['code']} {base['len']}b")
        print(f"[csti] {len(PAYLOADS)} payloads on {list(params.keys())}")

        findings = []
        for name in params:
            print(f"\n[csti] param '{name}'")
            for p in PAYLOADS:
                url_fn = lambda pl, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()}, name: pl}, doseq=True)))

                expected = None
                if "7*7" in p and "{{" in p:
                    expected = "49"

                r = probe.inject(url_fn, p, detect_markers=[expected] if expected else None)
                if not r["hit"]:
                    continue

                verified = probe.verify(url_fn, p,
                                        detect_markers=[expected] if expected else None, times=2)
                if not verified:
                    print(f"  · unverified: {p[:50]}")
                    continue

                sev = "high" if expected else "medium"
                print(f"  ✓ [{sev}] {p[:50]} -> {r['reason']}")
                findings.append({"param": name, "payload": p,
                                 "severity": sev, "verified": True})
                logger.finding("csti", sev, f"{name}={p[:50]} ({r['reason']})")

        print(f"\n[csti] total: {len(findings)}")
        return {"findings": findings, "stats": probe.summary()}
