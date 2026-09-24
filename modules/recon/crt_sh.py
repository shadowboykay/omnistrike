"""crt_sh — subdomain discovery via certificate transparency (crt.sh)"""
from core.http import HttpClient

class CrtSh:
    def run(self, session, logger):
        domain = session.target.replace("https://","").replace("http://","").split("/")[0]
        http = HttpClient(session, logger)
        print(f"[crt_sh] {domain}")
        r = http.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if not r or r.status_code != 200:
            print("  no data (crt.sh may rate-limit)"); return {"subdomains": []}
        try:
            data = r.json()
        except Exception:
            print("  bad json"); return {"subdomains": []}

        subs = set()
        for entry in data:
            for name in entry.get("name_value","").split("\n"):
                name = name.strip().lstrip("*.")
                if name and domain in name:
                    subs.add(name)
        subs = sorted(subs)
        for s in subs[:50]:
            print(f"  [+] {s}")
        if len(subs) > 50:
            print(f"  ... and {len(subs)-50} more")
        for s in subs:
            logger.finding("subdomain_ct","info",s)
        print(f"[crt_sh] {len(subs)} unique subdomains")
        return {"domain": domain, "subdomains": subs}
