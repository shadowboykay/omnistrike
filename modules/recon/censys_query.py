"""censys_query — query censys (needs CENSYS_API_ID + CENSYS_API_SECRET env)"""
import os
from core.http import HttpClient

class CensysQuery:
    def run(self, session, logger):
        api_id = os.environ.get("CENSYS_API_ID")
        api_secret = os.environ.get("CENSYS_API_SECRET")
        if not (api_id and api_secret):
            print("[censys] set CENSYS_API_ID + CENSYS_API_SECRET (free at censys.io)")
            return {"error": "no_api_key"}
        http = HttpClient(session, logger)
        q = session.target
        r = http.post("https://search.censys.io/api/v2/hosts/search",
                      json={"q":q,"per_page":25},
                      headers={"Content-Type":"application/json"},
                      auth=(api_id, api_secret))
        if not r or r.status_code != 200:
            print(f"  error: {r.status_code if r else 'no resp'}"); return {}
        try:
            data = r.json().get("result",{})
        except Exception: return {}
        hits = data.get("hits",[])
        print(f"[censys] {len(hits)} results")
        for h in hits[:15]:
            ip = h.get("ip","")
            services = [s.get("service_name","") for s in h.get("services",[])]
            print(f"  {ip} -> {services}")
            logger.finding("censys","info",f"{ip} {services}")
        return {"hits": hits}
