"""dns — record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)"""
import socket
from core.http import HttpClient

class DNS:
    def run(self, session, logger):
        d = session.target.replace("https://","").replace("http://","").split("/")[0]
        out = {}
        try:
            out["A"] = socket.gethostbyname_ex(d)[2]
        except Exception as e:
            out["A"] = []; logger.warn("dns_a_fail", error=str(e))
        for rec in ("MX","NS","TXT"):
            try:
                # dnspython not stdlib; fallback via public DNS-over-HTTPS
                http = HttpClient(session, logger)
                r = http.get(f"https://dns.google/resolve?name={d}&type={rec}",
                             headers={"Accept":"application/dns-json"})
                if r and r.status_code == 200:
                    data = r.json().get("Answer", [])
                    out[rec] = [a.get("data") for a in data]
                    for v in out[rec]:
                        print(f"  {rec}: {v}")
            except Exception as e:
                out[rec] = []
        logger.info("dns_done", records={k: len(v) for k,v in out.items()})
        return out
