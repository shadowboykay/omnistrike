"""http_request_splitting — HTTP response splitting via CRLF in headers/params"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.probe import Probe
from core.payload_source import get_payloads

# CRLF variants
CRLF_PAYLOADS = get_payloads("crlf")

# injection points
HEADERS = ["X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "Referer",
           "User-Agent", "X-Custom", "X-Originating-IP", "X-Client-IP"]

MARKERS = ["Injected-Header", "splitting", "evil.attacker.example",
           "Set-Cookie:sess=injected"]


class HttpRequestSplitting:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query)
        http = HttpClient(session, logger)
        probe = Probe(session, logger)
        probe.baseline_probe(target)

        findings = []

        # 1. query params
        if params:
            for name in params:
                for p in CRLF_PAYLOADS[:5]:
                    url_fn = lambda pl, u=u, params=params, name=name: urlunparse(
                        u._replace(query=urlencode({**{k: v[0] for k, v in params.items()}, name: pl}, doseq=True)))
                    r = probe.inject(url_fn, p, detect_markers=MARKERS)
                    if r["hit"]:
                        print(f"  [!] CRLF in param {name}: {p[:40]}")
                        findings.append({"location": "param", "name": name,
                                         "payload": p, "severity": "high"})
                        logger.finding("crlf_param", "high", f"{name}={p[:40]}")

        # 2. headers
        for h in HEADERS:
            for p in CRLF_PAYLOADS[:4]:
                r = http.get(target, headers={h: p})
                if not r: continue
                # check injected header appears
                if any(m in str(r.headers) for m in MARKERS):
                    print(f"  [!] CRLF in header {h}: {p[:40]}")
                    findings.append({"location": "header", "name": h,
                                     "payload": p, "severity": "critical"})
                    logger.finding("crlf_header", "critical", f"{h}={p[:40]}")
                # response splitting — two responses
                if "Injected-Header" in r.text or "HTTP/1.1 200" in r.text[:500]:
                    findings.append({"location": "header", "name": h, "payload": p,
                                     "type": "splitting", "severity": "critical"})
                    logger.finding("response_splitting", "critical", f"{h}={p[:40]}")

        print(f"[http_request_splitting] total: {len(findings)}")
        return {"findings": findings}
