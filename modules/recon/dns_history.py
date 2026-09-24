"""dns_history — historical DNS via securitytrails (needs ST_API_KEY env)"""
import os
from core.http import HttpClient

class DnsHistory:
    def run(self, session, logger):
        key = os.environ.get("ST_API_KEY")
        if not key:
            print("[dns_history] set ST_API_KEY (securitytrails.com)")
            return {"error": "no_api_key"}
        domain = session.target.replace("https://","").replace("http://","").split("/")[0]
        http = HttpClient(session, logger)
        headers = {"APIKEY": key}
        r = http.get(f"https://api.securitytrails.com/v1/history/{domain}/dns/a", headers=headers)
        if r and r.status_code == 200:
            try:
                records = r.json().get("records",[])
                print(f"[dns_history] {len(records)} records")
                ips = set()
                for rec in records[:50]:
                    for v in rec.get("values",[]):
                        ips.add(v.get("ip",""))
                for ip in sorted(ips)[:20]:
                    print(f"  {ip}")
                    logger.finding("dns_history","info",ip)
                return {"ips": sorted(ips)}
            except Exception: pass
        print("  no data")
        return {}
