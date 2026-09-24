"""ssti — SSTI scanner on Probe v2 with verify"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.probe import Probe
from core.payloads import get

EXPECT = [
    ("{{7*7}}", "49"), ("{{7*'7'}}", "7777777"), ("${7*7}", "49"),
    ("#{7*7}", "49"), ("<%= 7*7 %>", "49"), ("${{7*7}}", "49"),
    ("{{config}}", "SECRET"), ("{{self}}", "TemplateReference"),
    ("[[${7*7}]]", "49"), ("{%25 7*7 %25}", "49"),
]

class Ssti:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"name": ["test"]}

        probe = Probe(session, logger)
        base = probe.baseline_probe(target)
        if not base:
            print("[ssti] no baseline"); return {"findings": []}
        print(f"[ssti] baseline: {base['code']} {base['len']}b")

        payloads = get("ssti", limit=80, mutate_by=0)
        print(f"[ssti] {len(payloads)} payloads on {list(params.keys())}")

        findings = []
        for name in params:
            print(f"\n[ssti] param '{name}'")
            for p in payloads:
                url_fn = lambda pl, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()}, name: pl}, doseq=True))
                )
                # find expected result for this payload
                expected = None
                for test, exp in EXPECT:
                    if test == p:
                        expected = exp
                        break

                r = probe.inject(url_fn, p,
                                 detect_markers=[expected] if expected else None)
                if not r["hit"]:
                    continue

                # verify
                verified = probe.verify(url_fn, p,
                                        detect_markers=[expected] if expected else None, times=2)
                if not verified:
                    print(f"  · unverified: {p[:50]}"); continue

                sev = "critical"
                print(f"  ✓ [{sev}] {p[:50]} -> {r['reason']}")
                findings.append({"param": name, "payload": p,
                                 "severity": sev, "verified": True})
                logger.finding("ssti", sev, f"{name}={p[:50]} ({r['reason']})")
                break  # one per param

        print(f"\n[ssti] total: {len(findings)} verified")
        print(f"[ssti] stats: {probe.summary()}")
        return {"findings": findings, "stats": probe.summary()}
