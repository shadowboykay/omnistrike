"""asn_lookup — find ASN + IP ranges for an organization"""
from core.http import HttpClient

class AsnLookup:
    def run(self, session, logger):
        q = session.target
        http = HttpClient(session, logger)
        print(f"[asn_lookup] query: {q}")

        # try ip-api.com (free, no key)
        r = http.get(f"http://ip-api.com/json/{q}")
        if r and r.status_code == 200:
            try:
                data = r.json()
                if data.get("status") == "success":
                    print(f"  ASN: {data.get('as','')}")
                    print(f"  ISP: {data.get('isp','')}")
                    print(f"  Country: {data.get('country','')}")
                    logger.finding("asn","info",f"{q} -> {data.get('as','')}")
                    return {"asn": data.get("as"), "isp": data.get("isp"), "raw": data}
            except Exception: pass

        # fallback to bgpview
        r = http.get(f"https://api.bgpview.io/search?query_term={q}")
        if r and r.status_code == 200:
            try:
                data = r.json().get("data",{})
                asns = data.get("asns",[])
                for a in asns[:5]:
                    print(f"  ASN{a['asn']} {a.get('name','')}")
                    logger.finding("asn","info",f"AS{a['asn']} {a.get('name','')}")
                prefixes = data.get("ipv4_prefixes", [])
                for p in prefixes[:20]:
                    print(f"  {p.get('prefix','')}")
                return {"asns": asns, "prefixes": prefixes}
            except Exception: pass
        print("  no data")
        return {}
