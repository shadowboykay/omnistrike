"""s3_bucket — AWS S3 / Azure Blob / GCP Storage bucket enumeration"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient

S3_SUFFIXES = [".s3.amazonaws.com", ".s3.us-east-1.amazonaws.com",
               ".s3.us-west-2.amazonaws.com", ".s3.eu-west-1.amazonaws.com",
               ".s3-website-us-east-1.amazonaws.com", ".s3-website.eu-west-1.amazonaws.com"]

AZURE_SUFFIXES = [".blob.core.windows.net", ".web.core.windows.net"]

GCP_SUFFIXES = ["storage.googleapis.com"]

class S3Bucket:
    def run(self, session, logger):
        # build candidate names from target
        org = session.target.replace("https://","").replace("http://","").split("/")[0]
        org = org.split(".")[0]

        names = set()
        for base in [org, f"{org}-dev", f"{org}-prod", f"{org}-staging", f"{org}-test",
                     f"{org}-backup", f"{org}-files", f"{org}-assets", f"{org}-static",
                     f"{org}-media", f"{org}-uploads", f"{org}-data", f"{org}-logs",
                     f"{org}-cdn", f"{org}-web", f"{org}-app", f"{org}-api",
                     f"{org}-public", f"{org}-private", f"{org}-internal",
                     f"{org}backup", f"{org}files", f"{org}assets", f"{org}prod",
                     f"www.{org}", f"dev-{org}", f"prod-{org}", f"test-{org}"]:
            names.add(base)

        http = HttpClient(session, logger)
        found = []

        def check_s3(name):
            for suf in S3_SUFFIXES[:2]:
                url = f"https://{name}{suf}"
                r = http.get(url, allow_redirects=False)
                if not r: continue
                if r.status_code == 200:
                    return {"service":"s3","name":name,"url":url,"status":"PUBLIC"}
                if r.status_code == 403:
                    return {"service":"s3","name":name,"url":url,"status":"exists_private"}
            return None

        def check_azure(name):
            for suf in AZURE_SUFFIXES:
                url = f"https://{name}{suf}"
                r = http.get(url, allow_redirects=False)
                if r and r.status_code in (200, 400, 403):
                    return {"service":"azure","name":name,"url":url,"status":r.status_code}
            return None

        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = []
            for n in names:
                futs.append(ex.submit(check_s3, n))
                futs.append(ex.submit(check_azure, n))
            for f in as_completed(futs):
                res = f.result()
                if res:
                    found.append(res)
                    sev = "critical" if res.get("status") == "PUBLIC" else "info"
                    print(f"  [+] {res['service']}: {res['url']} ({res['status']})")
                    logger.finding("bucket", sev, f"{res['service']} {res['url']} {res['status']}")

        print(f"[s3_bucket] {len(found)} buckets for '{org}'")
        return {"candidates": list(names), "found": found}
