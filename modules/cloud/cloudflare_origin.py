"""cloudflare_origin — find real origin IP behind Cloudflare"""
from core.http import HttpClient
import socket

# known CF ranges (partial)
CF_RANGES = [
    "173.245.48.","103.21.244.","103.22.200.","103.31.4.","141.101.64.","108.162.192.",
    "190.93.240.","188.114.96.","197.234.240.","198.41.128.","162.158.","104.16.",
    "104.17.","104.18.","104.19.","104.20.","104.21.","104.22.","104.23.","104.24.",
    "104.25.","104.26.","104.27.","172.64.","172.65.","172.66.","172.67.","172.68.",
]

class CloudflareOrigin:
    def run(self, session, logger):
        domain = session.target.replace("https://","").replace("http://","").split("/")[0]
        http = HttpClient(session, logger)
        print(f"[cf_origin] finding origin for {domain}")

        candidates = set()

        # 1. crt.sh historical subdomains that may not be behind CF
        r = http.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if r and r.status_code == 200:
            try:
                for entry in r.json()[:200]:
                    for n in entry.get("name_value","").split("\n"):
                        n = n.strip().lstrip("*.")
                        if n and n != domain:
                            try:
                                ip = socket.gethostbyname(n)
                                candidates.add((n, ip))
                            except Exception: pass
            except Exception: pass

        # 2. filter to non-CF
        origins = []
        for name, ip in candidates:
            if any(ip.startswith(p) for p in CF_RANGES):
                continue
            origins.append({"host":name,"ip":ip})
            print(f"  [+] possible origin: {name} -> {ip}")
            logger.finding("cf_origin","high",f"{name} -> {ip}")

        # 3. direct IP check for the apex
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            non_cf = [ip for ip in ips if not any(ip.startswith(p) for p in CF_RANGES)]
            if non_cf:
                print(f"  [+] apex non-CF: {non_cf}")
                logger.finding("cf_origin","critical",f"apex -> {non_cf}")
                origins.extend([{"host":domain,"ip":ip} for ip in non_cf])
        except Exception: pass

        print(f"[cf_origin] {len(origins)} origin candidates")
        return {"origins": origins}
