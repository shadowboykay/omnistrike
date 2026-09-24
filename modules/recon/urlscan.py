"""urlscan — query urlscan.io for historical scans of domain"""
from core.http import HttpClient

class Urlscan:
    def run(self, session, logger):
        domain = session.target.replace("https://","").replace("http://","").split("/")[0]
        http = HttpClient(session, logger)
        print(f"[urlscan] {domain}")
        r = http.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100")
        if not r or r.status_code != 200:
            print(f"  error: {r.status_code if r else 'no resp'}"); return {}
        try:
            data = r.json()
        except Exception:
            return {}
        results = data.get("results", [])
        print(f"  {len(results)} scans")
        ips, domains, urls = set(), set(), set()
        for res in results[:50]:
            page = res.get("page", {})
            ips.add(page.get("ip",""))
            domains.add(page.get("domain",""))
            urls.add(page.get("url",""))
        ips.discard("")
        domains.discard("")
        urls.discard("")
        for ip in sorted(ips)[:10]:
            print(f"  ip: {ip}")
            logger.finding("urlscan_ip","info",ip)
        for d in sorted(domains)[:20]:
            if d != domain:
                print(f"  domain: {d}")
                logger.finding("urlscan_domain","info",d)
        print(f"[urlscan] {len(ips)} ips, {len(domains)} domains")
        return {"ips": sorted(ips), "domains": sorted(domains), "urls": sorted(urls)[:50]}
