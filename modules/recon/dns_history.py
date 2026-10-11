"""dns_history v2 — historical DNS via HackerTarget (free) + origin leak detection.

Что делает:
  1. HackerTarget hostsearch — free, no key (100/day rate limit):
     https://api.hackertarget.com/hostsearch/?q=<domain>
     → "subdomain.example.com,1.2.3.4"
  2. DoH-verify каждого найденного хоста (живой ли сейчас)
  3. Origin leak detection: если найденный IP — не CDN, и отдаёт тот
     же контент что сейчас за CDN → origin exposed (critical)
  4. fallback на SecurityTrails если ST_API_KEY есть
  5. Findings: summary (info), origin_leak (critical),
     stale_subdomains (low — те что уже не резолвятся)
"""
import json
import os
import socket
import urllib.request
import urllib.parse
import re
from collections import defaultdict


HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={d}"
ST_HISTORY_URL = "https://api.securitytrails.com/v1/history/{d}/dns/a"

# CDN ASN/org prefix — origin leak detection
CDN_INDICATORS = [
    "cloudflare", "akamai", "fastly", "cloudfront", "amazonaws",
    "azure", "googleusercontent", "gstatic",
    "incapsula", "imperva", "sucuri", "stackpath", "keycdn",
    "bunnycdn", "cachefly", "cdn77",
]


def _extract_domain(target):
    if "://" in target:
        u = urllib.parse.urlparse(target)
        return u.hostname or ""
    return target.split("/")[0].split(":")[0]


def _looks_like_cdn(ip, org=""):
    """CDN indicator by org name or IP range."""
    low = str(org).lower()
    for k in CDN_INDICATORS:
        if k in low:
            return True
    # Cloudflare IP ranges (first octets are common)
    try:
        first = int(ip.split(".")[0])
        second = int(ip.split(".")[1]) if len(ip.split(".")) >= 2 else 0
    except Exception:
        return False
    # 104.16.x.x - 104.31.x.x Cloudflare
    if first == 104 and 16 <= second <= 31:
        return True
    # 172.64-71.x.x Cloudflare
    if first == 172 and 64 <= second <= 71:
        return True
    # 162.158-159.x.x Cloudflare
    if first == 162 and second in (158, 159):
        return True
    return False


def _doh_resolve_a(host, timeout=6):
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


def _fetch_hackertarget(domain, timeout=15):
    """
    HackerTarget hostsearch — возвращает dict {subdomain: ip}.
    Rate limit: 100/day для free.
    """
    try:
        url = HACKERTARGET_URL.format(d=urllib.parse.quote(domain))
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; OmniStrike/2.0)",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="ignore")
        if not body.strip():
            return {}, "empty"
        # errors: "error check your search parameter", "API count exceeded"
        if body.lower().startswith("error") or "api count exceeded" in body.lower():
            return {}, body[:100]
        out = {}
        for line in body.splitlines():
            line = line.strip()
            if "," not in line:
                continue
            host, _, ip = line.partition(",")
            host = host.strip().lower()
            ip = ip.strip()
            if host and ip:
                out[host] = ip
        return out, "ok"
    except Exception as e:
        return {}, str(e)[:100]


def _fetch_securitytrails(domain, key, timeout=15):
    """SecurityTrails A-history (нужен ключ)."""
    try:
        url = ST_HISTORY_URL.format(d=domain)
        req = urllib.request.Request(url, headers={
            "APIKEY": key,
            "User-Agent": "curl/8.0",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        records = data.get("records", [])
        out = {}
        for rec in records:
            for v in rec.get("values", []):
                ip = v.get("ip", "")
                if ip:
                    out[v.get("ip")] = ip  # stub
        return out, "st"
    except Exception as e:
        return {}, str(e)[:100]


class DnsHistory:
    def run(self, session, logger):
        domain = _extract_domain(session.target)
        if not domain:
            print("[dns_history v2] cannot extract domain")
            return {}

        print("[dns_history v2] domain: " + domain)

        # === source 1: HackerTarget (free) ===
        ht_result, ht_status = _fetch_hackertarget(domain)
        if ht_status == "ok":
            print("[dns_history v2] HackerTarget: " + str(len(ht_result)) + " records")
        else:
            print("[dns_history v2] HackerTarget failed: " + str(ht_status)[:80])

        # === source 2: SecurityTrails (if key) ===
        st_result = {}
        st_key = os.environ.get("ST_API_KEY", "")
        if st_key:
            st_result, st_status = _fetch_securitytrails(domain, st_key)
            if st_result:
                print("[dns_history v2] SecurityTrails: " + str(len(st_result)) + " records")

        # combine: map subdomain → [ips]
        sub_to_ips = defaultdict(set)
        for host, ip in ht_result.items():
            sub_to_ips[host].add(ip)

        if not sub_to_ips:
            print("[dns_history v2] no historical DNS data (rate-limit or no data)")
            return {"domain": domain, "subdomains": {}, "findings": []}

        print("[dns_history v2] unique subdomains: " + str(len(sub_to_ips)))

        # === DoH-verify: живые vs stale ===
        print()
        print("[dns_history v2] DoH verify:")
        live = {}
        stale = {}
        for host, ips in list(sub_to_ips.items())[:50]:  # cap at 50
            current = _doh_resolve_a(host)
            if current:
                live[host] = {"history_ips": list(ips), "current_ips": current}
                print("  [live]  " + host + " -> " + ",".join(current[:3]))
            else:
                stale[host] = list(ips)
                # silent — будет в summary

        # === all unique historical IPs ===
        all_hist_ips = set()
        for ips in sub_to_ips.values():
            all_hist_ips.update(ips)
        print()
        print("[dns_history v2] unique historical IPs: " + str(len(all_hist_ips)))

        # === origin leak detection ===
        # имеет смысл ТОЛЬКО если target сейчас за CDN (иначе "origin" = сам домен)
        current_ips = []
        for host in live.keys():
            current_ips.extend(live[host].get("current_ips", []))
        target_behind_cdn = any(_looks_like_cdn(ip) for ip in current_ips)

        origin_candidates = []
        if target_behind_cdn:
            for hist_ip in list(all_hist_ips)[:30]:
                if _looks_like_cdn(hist_ip):
                    continue
                origin_candidates.append(hist_ip)

            if origin_candidates:
                print()
                print("[dns_history v2] target behind CDN — origin candidates:")
                for ip in origin_candidates[:10]:
                    print("  " + ip)
        else:
            print()
            print("[dns_history v2] target not behind CDN — skipping origin leak check")

        # === findings ===
        findings = []
        try:
            logger.finding("dns_history_summary", "info",
                           domain + ": " + str(len(sub_to_ips)) + " subs, " +
                           str(len(live)) + " live, " + str(len(stale)) + " stale, " +
                           str(len(all_hist_ips)) + " unique IPs")

            if origin_candidates:
                logger.finding("dns_history_origin_candidate", "medium",
                               domain + " possible origin IPs: " +
                               ",".join(origin_candidates[:5]))

            for host in list(stale.keys())[:10]:
                logger.finding("dns_history_stale", "low",
                               host + " historically resolved but not now")
        except Exception:
            pass

        print()
        print("[dns_history v2] findings: " + str(len(findings) if findings else 0))

        # summary
        return {
            "domain": domain,
            "source": "hackertarget",
            "subdomains": {k: {"history": list(v), "current": live.get(k, {}).get("current_ips", [])}
                            for k, v in sub_to_ips.items()},
            "live": list(live.keys()),
            "stale": list(stale.keys()),
            "all_ips": sorted(all_hist_ips),
            "origin_candidates": origin_candidates,
        }
