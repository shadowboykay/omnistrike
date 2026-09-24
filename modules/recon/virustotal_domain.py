"""virustotal_domain — VT domain report + subdomains (needs VT_API_KEY env)"""
import os
from core.http import HttpClient

class VirustotalDomain:
    def run(self, session, logger):
        key = os.environ.get("VT_API_KEY")
        if not key:
            print("[virustotal] set VT_API_KEY (free at virustotal.com)")
            return {"error": "no_api_key"}
        domain = session.target.replace("https://","").replace("http://","").split("/")[0]
        http = HttpClient(session, logger)
        headers = {"x-apikey": key}
        r = http.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
        if r and r.status_code == 200:
            attrs = r.json().get("data",{}).get("attributes",{})
            stats = attrs.get("last_analysis_stats",{})
            print(f"[virustotal] {domain}: {stats}")
            logger.finding("virustotal","info",f"{domain} {stats}")
        r2 = http.get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100",
                      headers=headers)
        subs = []
        if r2 and r2.status_code == 200:
            for item in r2.json().get("data",[]):
                subs.append(item.get("id",""))
            print(f"  {len(subs)} subdomains")
            for s in subs[:20]:
                print(f"  {s}")
                logger.finding("vt_subdomain","info",s)
        return {"subdomains": subs}
