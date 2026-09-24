# core/free_sources.py — free OSINT sources (no API key required)
import requests
import urllib3
urllib3.disable_warnings()
from urllib.parse import quote


def fetch(url, timeout=15, headers=None):
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers=headers or {"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return r
    except Exception:
        pass
    return None


# ============ Shodan InternetDB (free, no key) ============
def shodan_internetdb(ip):
    """
    Shodan InternetDB — бесплатная альтернатива Shodan API.
    Дает: ports, cpes, hostnames, tags, vulns.
    """
    r = fetch(f"https://internetdb.shodan.io/{ip}")
    if not r:
        return None
    try:
        return r.json()
    except Exception:
        return None


# ============ URLhaus (abuse.ch, free) ============
def urlhaus_lookup(url):
    """Check URL against URLhaus malware database."""
    r = fetch("https://urlhaus-api.abuse.ch/v1/url/",
              timeout=15, headers={"User-Agent": "omnistrike"})
    # URLhaus requires POST; skip for now
    return None


# ============ crt.sh (certificate transparency, free) ============
def crtsh_domains(domain):
    """Get subdomains from Certificate Transparency logs."""
    r = fetch(f"https://crt.sh/?q=%25.{domain}&output=json")
    if not r:
        return []
    try:
        data = r.json()
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                n = name.strip().lstrip("*.")
                if n and domain in n:
                    subs.add(n)
        return sorted(subs)
    except Exception:
        return []


# ============ GreyNoise Community (free tier) ============
def greynoise(ip):
    """GreyNoise Community API — check if IP is known scanner."""
    r = fetch(f"https://api.greynoise.io/v3/community/{ip}")
    if not r:
        return None
    try:
        return r.json()
    except Exception:
        return None


# ============ HackerTarget (free tier) ============
def hackertarget_hosts(domain):
    r = fetch(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    if not r:
        return []
    lines = [l for l in r.text.splitlines() if l]
    return lines[:200]


# ============ ThreatMiner (free) ============
def threatminer_domain(domain):
    r = fetch(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5")
    if not r:
        return {}
    try:
        return r.json()
    except Exception:
        return {}


# ============ Cisco Talos reputation (free-ish) ============
def talos_ip(ip):
    r = fetch(f"https://talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Flocation%2Fip%2F{ip}%2Fdetails%2F&query_entry={ip}")
    if not r:
        return None
    try:
        return r.json()
    except Exception:
        return None


# ============ Unified enrichment for IP ============
def enrich_ip(ip):
    """Gather IP info from all free sources."""
    out = {"ip": ip}
    shodan = shodan_internetdb(ip)
    if shodan:
        out["ports"] = shodan.get("ports", [])
        out["cpes"] = shodan.get("cpes", [])
        out["hostnames"] = shodan.get("hostnames", [])
        out["tags"] = shodan.get("tags", [])
        out["vulns"] = shodan.get("vulns", [])
    gn = greynoise(ip)
    if gn:
        out["greynoise_classification"] = gn.get("classification", "")
        out["greynoise_name"] = gn.get("name", "")
    return out


# ============ Unified enrichment for domain ============
def enrich_domain(domain):
    out = {"domain": domain}
    subs = crtsh_domains(domain)
    if subs:
        out["crtsh_subdomains"] = subs
    ht = hackertarget_hosts(domain)
    if ht:
        out["hackertarget_hosts"] = ht
    return out


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        q = sys.argv[1]
        import json
        if q[0].isdigit():
            print(json.dumps(enrich_ip(q), indent=2))
        else:
            print(json.dumps(enrich_domain(q), indent=2))
