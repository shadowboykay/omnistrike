"""azure_blob — Azure Blob Storage enumeration"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient

class AzureBlob:
    def run(self, session, logger):
        org = session.target.replace("https://","").replace("http://","").split("/")[0].split(".")[0]
        http = HttpClient(session, logger)

        # generate container names
        containers = ["", "public","private","backup","files","data","assets","static","media",
                      "uploads","logs","config","backups","db","database","images","docs",
                      "web","www","cdn","content"]
        accounts = [org, f"{org}storage", f"{org}files", f"{org}backup", f"storage{org}"]

        found = []
        def check(acct, container):
            url = f"https://{acct}.blob.core.windows.net/{container}?restype=container&comp=list"
            r = http.get(url, allow_redirects=False)
            if not r: return None
            if r.status_code == 200 and "<EnumerationResults" in r.text:
                return {"account":acct,"container":container,"url":url,"status":"PUBLIC"}
            if r.status_code == 403 and "AuthenticationFailed" not in r.text:
                return {"account":acct,"container":container,"url":url,"status":"exists"}
            return None

        with ThreadPoolExecutor(max_workers=15) as ex:
            futs = []
            for a in accounts[:3]:
                for c in containers:
                    futs.append(ex.submit(check, a, c))
            for f in as_completed(futs):
                res = f.result()
                if res:
                    found.append(res)
                    sev = "critical" if res["status"] == "PUBLIC" else "info"
                    print(f"  [+] {res['account']}/{res['container']} ({res['status']})")
                    logger.finding("azure_blob", sev, f"{res['account']}/{res['container']} {res['status']}")

        print(f"[azure_blob] {len(found)} containers")
        return {"found": found}
