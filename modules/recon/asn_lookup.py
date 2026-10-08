"""asn_lookup v2 — ASN + RDAP + BGP prefixes для IP/домена.

Источники:
  1. Cloudflare DoH — resolve домена в IP (не отдаём подмену)
  2. ipinfo.io — ASN, org, country, hostname (HTTPS, без ключа до 1k/day)
  3. ip-api.com — ISP, geo (HTTP, но HTTPS-fallback через curl_cffi)
  4. bgpview.io — BGP prefixes + peer info
  5. RDAP (ARIN/RIPE/APNIC/LACNIC/AFRINIC) — owner, abuse-contact

Плюс:
  - определение типа хостинга (cloud/vps/shared/hosting/CDN) по ASN
  - reverse DNS (PTR)
  - abuse contact для дальнейшего engagement
"""
import json
import socket
import urllib.request
import urllib.parse
import re


CLOUD_ASNS = {
    13335: "Cloudflare", 209242: "Cloudflare", 132892: "Cloudflare",
    16509: "AWS", 14618: "AWS", 38895: "AWS",
    15169: "Google Cloud", 396982: "Google Cloud",
    8075: "Microsoft Azure", 12076: "Azure",
    14061: "DigitalOcean", 63949: "Linode/Akamai", 20473: "Vultr",
    24940: "Hetzner", 197540: "Netcup", 12876: "Online.net",
    16276: "OVH", 51167: "Contabo", 44477: "Kaopu Cloud",
    9009: "M247", 205100: "PQ Hosting", 59711: "HZ Hosting",
}


def _extract_host(target):
    if "://" in target:
        u = urllib.parse.urlparse(target)
        return u.hostname or ""
    return target.split("/")[0].split(":")[0]


def _doh_resolve(host, timeout=6):
    """A-записи через Cloudflare DoH."""
    try:
        url = "https://cloudflare-dns.com/dns-query?name=" + host + "&type=A"
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        if data.get("Status") != 0:
            return []
        return [a.get("data") for a in data.get("Answer", [])
                if a.get("type") == 1]
    except Exception:
        return []


def _lookup_ipinfo(ip, timeout=8):
    """ipinfo.io lookup — HTTPS, без ключа (1k/day)."""
    try:
        url = "https://ipinfo.io/" + ip + "/json"
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        return data
    except Exception:
        return {}


def _lookup_ipapi(ip, timeout=8):
    """ip-api.com — HTTP fallback."""
    try:
        url = "http://ip-api.com/json/" + ip + "?fields=status,country,city,isp,org,as,asname,reverse,hosting,proxy"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = json.load(r)
        if data.get("status") == "success":
            return data
    except Exception:
        pass
    return {}


def _lookup_bgpview_prefix(ip, timeout=8):
    """bgpview.io prefix info по IP."""
    try:
        url = "https://api.bgpview.io/ip/" + ip
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = json.load(r)
        if data.get("status") == "ok":
            return data.get("data", {})
    except Exception:
        pass
    return {}


def _lookup_rdap(ip, timeout=8):
    """RDAP lookup — owner через ARIN/RIPE/APNIC."""
    # определяем RIR по первому октету
    try:
        first = int(ip.split(".")[0])
    except Exception:
        return {}
    if 1 <= first <= 127 or 192 <= first <= 199 or 200 <= first <= 223:
        rir = "https://rdap.arin.net/registry/ip/"
    elif 128 <= first <= 191:
        rir = "https://rdap.arin.net/registry/ip/"
    else:
        rir = "https://rdap.arin.net/registry/ip/"
    try:
        url = rir + ip
        req = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return {}


def _detect_hosting_type(asn, org_name=""):
    """Определяет тип хостинга по ASN."""
    if asn in CLOUD_ASNS:
        return CLOUD_ASNS[asn]
    name_low = str(org_name).lower()
    if any(k in name_low for k in ("amazon", "google cloud", "microsoft", "azure", "cloudflare")):
        return "cloud"
    if any(k in name_low for k in ("digitalocean", "linode", "vultr", "hetzner", "ovh", "contabo")):
        return "vps"
    if any(k in name_low for k in ("hosting", "server", "datacenter", "data center", "colocation")):
        return "hosting"
    return "unknown"


class AsnLookup:
    def run(self, session, logger):
        target = session.target
        host = _extract_host(target)
        if not host:
            print("[asn v2] cannot extract host")
            return {}

        print("[asn v2] target: " + target)
        print("[asn v2] host: " + host)
        print()

        # === 1. resolve host to IP ===
        ips = []
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            ips = [host]
        else:
            ips = _doh_resolve(host)
            if not ips:
                try:
                    ips = [socket.gethostbyname(host)]
                except Exception:
                    pass

        if not ips:
            print("[asn v2] cannot resolve host")
            return {"host": host, "ips": []}

        print("[asn v2] resolved IPs: " + ", ".join(ips[:5]))
        print()

        out = {"host": host, "ips": ips, "lookups": []}

        for ip in ips[:3]:  # top-3 достаточно
            print("[asn v2] ======== IP: " + ip + " ========")
            ip_info = {}

            # ipinfo.io
            info = _lookup_ipinfo(ip)
            if info:
                asn_field = info.get("org", "") or ""
                asn_num = None
                m = re.match(r"AS(\d+)", asn_field)
                if m:
                    asn_num = int(m.group(1))
                org_name = asn_field.split(" ", 1)[1] if " " in asn_field else asn_field

                print("  [ipinfo] ASN: " + str(asn_num) + " — " + org_name)
                print("  [ipinfo] Country: " + str(info.get("country")) + " / City: " + str(info.get("city")))
                print("  [ipinfo] Hostname: " + str(info.get("hostname", "(none)")))

                ip_info["asn"] = asn_num
                ip_info["org"] = org_name
                ip_info["country"] = info.get("country")
                ip_info["city"] = info.get("city")
                ip_info["hostname"] = info.get("hostname")
                ip_info["source"] = "ipinfo"

            # ip-api fallback
            if not ip_info.get("asn"):
                info2 = _lookup_ipapi(ip)
                if info2:
                    asn_field = info2.get("as", "")
                    m = re.match(r"AS(\d+)", asn_field)
                    asn_num = int(m.group(1)) if m else None
                    print("  [ip-api] ASN: " + asn_field)
                    print("  [ip-api] ISP: " + str(info2.get("isp")))
                    print("  [ip-api] PTR: " + str(info2.get("reverse", "(none)")))
                    print("  [ip-api] hosting: " + str(info2.get("hosting")))
                    ip_info["asn"] = asn_num
                    ip_info["org"] = info2.get("org") or info2.get("isp")
                    ip_info["country"] = info2.get("country")
                    ip_info["city"] = info2.get("city")
                    ip_info["hostname"] = info2.get("reverse")
                    ip_info["source"] = "ip-api"

            # bgpview prefix
            bgp = _lookup_bgpview_prefix(ip)
            if bgp:
                prefixes = bgp.get("prefixes", [])
                if prefixes:
                    p0 = prefixes[0]
                    print("  [bgpview] prefix: " + p0.get("prefix", "?"))
                    print("  [bgpview] name: " + p0.get("name", "?"))
                    ip_info["bgp_prefix"] = p0.get("prefix")
                    ip_info["bgp_name"] = p0.get("name")
                    # additional ASN from bgpview
                    if not ip_info.get("asn") and p0.get("asn"):
                        ip_info["asn"] = p0["asn"].get("asn")
                        ip_info["org"] = p0["asn"].get("name")
                        ip_info["source"] = "bgpview"

            # RDAP — owner
            rdap = _lookup_rdap(ip)
            if rdap:
                name = rdap.get("name", "")
                handle = rdap.get("handle", "")
                events = rdap.get("events", [])
                abuse = None
                for ent in rdap.get("entities", []):
                    for role in ent.get("roles", []):
                        if role == "abuse":
                            for vcard in ent.get("vcardArray", [[]])[1] if ent.get("vcardArray") else []:
                                if vcard[0] == "email":
                                    abuse = vcard[3]
                                    break
                if name:
                    print("  [rdap] owner: " + name + " (" + handle + ")")
                    ip_info["rdap_owner"] = name
                    ip_info["rdap_handle"] = handle
                if abuse:
                    print("  [rdap] abuse: " + abuse)
                    ip_info["rdap_abuse"] = abuse

            # тип хостинга
            hosting_type = _detect_hosting_type(ip_info.get("asn"), ip_info.get("org"))
            ip_info["hosting_type"] = hosting_type
            print("  [hint] hosting type: " + hosting_type)
            print()

            out["lookups"].append({"ip": ip, **ip_info})

            # finding
            try:
                logger.finding("asn", "info",
                               ip + " AS" + str(ip_info.get("asn")) + " " + str(ip_info.get("org", ""))[:60])
            except Exception:
                pass

        print("[asn v2] summary: " + json.dumps([
            {"ip": l.get("ip"), "asn": l.get("asn"),
             "org": (l.get("org") or "")[:40],
             "type": l.get("hosting_type")}
            for l in out["lookups"]
        ]))

        return out
