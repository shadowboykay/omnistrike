"""domain — domain OSINT: WHOIS + DNS records + registrar hint"""
from core.http import HttpClient

class Domain:
    def run(self, session, logger):
        d = session.target.replace("https://","").replace("http://","").split("/")[0]
        http = HttpClient(session, logger)
        print(f"[domain] {d}")

        records = {}
        for rec in ("A","AAAA","MX","NS","TXT","SOA","CNAME","CAA"):
            r = http.get(f"https://dns.google/resolve?name={d}&type={rec}",
                         headers={"Accept":"application/dns-json"})
            if not r: continue
            data = r.json().get("Answer", [])
            vals = [a.get("data") for a in data]
            if vals:
                records[rec] = vals
                for v in vals[:3]:
                    print(f"  {rec:5s}: {v}")

        # whois via web (rdap)
        r = http.get(f"https://rdap.org/domain/{d}")
        rdap = {}
        if r and r.status_code == 200:
            try:
                rdap = r.json()
                for ev in rdap.get("events", []):
                    if ev.get("eventAction") in ("registration","expiration","last changed"):
                        print(f"  {ev['eventAction']}: {ev['eventDate']}")
            except Exception: pass

        logger.info("domain_done", d=d, records=list(records.keys()))
        return {"domain": d, "records": records, "rdap": rdap}
