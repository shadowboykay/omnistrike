"""shodan_query — query shodan (needs free API key via SHODAN_KEY env)"""
import os
from core.http import HttpClient

class ShodanQuery:
    def run(self, session, logger):
        key = os.environ.get("SHODAN_KEY")
        if not key:
            print("[shodan] SHODAN_KEY env not set")
            print("  export SHODAN_KEY=your_key  (free at account.shodan.io)")
            return {"error": "no_api_key"}

        http = HttpClient(session, logger)
        q = session.target
        r = http.get(f"https://api.shodan.io/shodan/host/search?key={key}&query={q}")
        if not r or r.status_code != 200:
            print(f"  error: {r.status_code if r else 'no resp'}"); return {}
        try:
            data = r.json()
        except Exception:
            return {}
        total = data.get("total", 0)
        print(f"[shodan] {total} results for '{q}'")
        for m in data.get("matches", [])[:20]:
            ip = m.get("ip_str","")
            port = m.get("port","")
            org = m.get("org","")
            print(f"  {ip}:{port} {org}")
            logger.finding("shodan","info",f"{ip}:{port} {org}")
        return {"total": total, "matches": data.get("matches", [])[:50]}
