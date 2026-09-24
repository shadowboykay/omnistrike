"""ip — IP OSINT: geo, ASN, reverse DNS"""
from core.http import HttpClient
import socket

class Ip:
    def run(self, session, logger):
        ip = session.target
        http = HttpClient(session, logger)
        print(f"[ip] {ip}")

        # reverse DNS
        try:
            rdns = socket.gethostbyaddr(ip)[0]
            print(f"  PTR: {rdns}")
        except Exception:
            rdns = None

        # geo via ipinfo.io (free, no key needed for basic)
        r = http.get(f"https://ipinfo.io/{ip}/json")
        info = {}
        if r and r.status_code == 200:
            try:
                info = r.json()
                for k in ("city","region","country","org","hostname","timezone"):
                    if info.get(k):
                        print(f"  {k}: {info[k]}")
            except Exception:
                pass

        logger.finding("ip","info",f"{ip} {info.get('org','')}")
        return {"ip": ip, "ptr": rdns, "info": info}
