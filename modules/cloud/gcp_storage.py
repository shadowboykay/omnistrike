"""gcp_storage — Google Cloud Storage bucket enumeration"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient

class GcpStorage:
    def run(self, session, logger):
        org = session.target.replace("https://","").replace("http://","").split("/")[0].split(".")[0]
        http = HttpClient(session, logger)
        names = set()
        for base in [org, f"{org}-dev", f"{org}-prod", f"{org}-backup", f"{org}-files",
                     f"{org}-data", f"{org}-static", f"{org}-assets", f"{org}-uploads",
                     f"{org}-media", f"{org}-public", f"{org}-private", f"{org}-logs",
                     f"{org}backup", f"{org}files", f"{org}assets", f"{org}prod"]:
            names.add(base)

        found = []
        def check(name):
            url = f"https://storage.googleapis.com/{name}"
            r = http.get(url)
            if not r: return None
            if r.status_code == 200 and ("ListBucketResult" in r.text or "<Contents>" in r.text):
                return {"name":name,"url":url,"status":"PUBLIC"}
            if r.status_code == 403:
                return {"name":name,"url":url,"status":"exists"}
            return None

        with ThreadPoolExecutor(max_workers=15) as ex:
            futs = [ex.submit(check, n) for n in names]
            for f in as_completed(futs):
                res = f.result()
                if res:
                    found.append(res)
                    sev = "critical" if res["status"] == "PUBLIC" else "info"
                    print(f"  [+] {res['name']} ({res['status']})")
                    logger.finding("gcp_bucket", sev, f"{res['name']} {res['status']}")

        print(f"[gcp_storage] {len(found)} buckets")
        return {"found": found}
