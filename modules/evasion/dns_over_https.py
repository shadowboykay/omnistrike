"""dns_over_https — resolve via DoH to bypass local DNS filters"""
from core.http import HttpClient

PROVIDERS = {
    "google":     "https://dns.google/resolve?name={n}&type=A",
    "cloudflare": "https://cloudflare-dns.com/dns-query?name={n}&type=A",
    "quad9":      "https://dns.quad9.net:5053/dns-query?name={n}&type=A",
}

class DnsOverHttps:
    def run(self, session, logger):
        host = session.target.replace("https://","").replace("http://","").split("/")[0]
        http = HttpClient(session, logger)
        print(f"[doh] resolving {host} via DoH providers")
        results = {}
        for name, tpl in PROVIDERS.items():
            url = tpl.format(n=host)
            r = http.get(url, headers={"Accept":"application/dns-json"})
            if not r or r.status_code != 200:
                print(f"  {name:12s} error {r.status_code if r else 'no resp'}")
                continue
            try:
                answers = r.json().get("Answer", [])
                ips = [a.get("data","") for a in answers if a.get("type") == 1]
                results[name] = ips
                print(f"  {name:12s} {ips}")
                for ip in ips:
                    logger.finding("doh_resolve","info",f"{name}: {host} -> {ip}")
            except Exception as e:
                print(f"  {name}: parse error")
        return {"results": results}
