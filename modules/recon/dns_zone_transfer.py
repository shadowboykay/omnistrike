"""dns_zone_transfer — try AXFR on all nameservers"""
import subprocess, socket
from core.http import HttpClient

class DnsZoneTransfer:
    def run(self, session, logger):
        domain = session.target.replace("https://","").replace("http://","").split("/")[0]
        http = HttpClient(session, logger)
        print(f"[axfr] {domain}")

        # get NS via DoH
        r = http.get(f"https://dns.google/resolve?name={domain}&type=NS",
                     headers={"Accept":"application/dns-json"})
        if not r: return {}
        ns_list = [a.get("data","").rstrip(".") for a in r.json().get("Answer",[])]
        print(f"  NS: {ns_list}")

        found = []
        for ns in ns_list:
            try:
                ips = socket.gethostbyname_ex(ns)[2]
            except Exception:
                ips = []
            for ip in ips[:2]:
                # use dig/nslookup if available, else manual
                try:
                    out = subprocess.run(["nslookup","-type=AXFR",domain,ns],
                                        capture_output=True, text=True, timeout=10)
                    text = out.stdout + out.stderr
                    if "Transfer failed" not in text and "AXFR" in text or len(text) > 500:
                        found.append({"ns":ns,"ip":ip,"size":len(text)})
                        print(f"  [!] AXFR works on {ns} ({ip})")
                        logger.finding("dns_axfr","critical",f"AXFR {ns}")
                except FileNotFoundError:
                    print("  nslookup not found — install: pkg install dnsutils")
                    return {}
                except Exception as e:
                    pass

        if not found:
            print("  no AXFR allowed")
        print(f"[axfr] {len(found)} servers allow zone transfer")
        return {"nameservers": ns_list, "vulnerable": found}
