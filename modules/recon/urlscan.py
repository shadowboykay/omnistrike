"""urlscan v2 — urlscan.io search API + sensitive URL mining.

API (free, no key для search):
  https://urlscan.io/api/v1/search/?q=domain:<domain>&size=100

Что делает:
  1. Поиск всех публичных сканов домена
  2. Поля: URL, IP, domain, time, ASN, country, server
  3. Фильтр: последние 90 дней (актуальное)
  4. Unique: IPs, domains, URLs, ASNs, countries
  5. Sensitive URL detection: admin/login/api/backup/upload
  6. Findings: summary (info) + IPs (info) + sensitive URLs (medium)

Rate limit: urlscan free ~100 req/day. Respect Retry-After header.
"""
import json
import urllib.request
import urllib.parse
import re
from datetime import datetime, timedelta, timezone
from collections import defaultdict


URLSCAN_API = "https://urlscan.io/api/v1/search/"

SENSITIVE_URL_KEYS = [
    "/admin", "/login", "/signin", "/api/", "/backup",
    "/upload", "/file", "/download", ".env", ".git",
    "/config", "/setup", "/install", "/debug", "/test",
    "/phpmyadmin", "/wp-admin", "/wp-login",
    "/graphql", "/swagger", "/api-docs",
]


def _extract_domain(target):
    if "://" in target:
        u = urllib.parse.urlparse(target)
        return u.hostname or ""
    return target.split("/")[0].split(":")[0]


def _urlscan_search(domain, size=100, timeout=20):
    """Поиск сканов через urlscan.io (free, no key)."""
    url = URLSCAN_API + "?" + urllib.parse.urlencode({
        "q": "domain:" + domain,
        "size": str(size),
    })
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; OmniStrike/2.0)",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="ignore")
        if not body.strip():
            return {}, "empty"
        data = json.loads(body)
        return data, "ok"
    except Exception as e:
        return {}, str(e)[:150]


def _parse_time(ts):
    """ISO timestamp → aware datetime или None."""
    if not ts:
        return None
    try:
        # urlscan возвращает с миллисекундами и Z
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _is_sensitive(url):
    low = url.lower()
    for k in SENSITIVE_URL_KEYS:
        if k in low:
            return True
    return False


class Urlscan:
    def run(self, session, logger):
        domain = _extract_domain(session.target)
        if not domain:
            print("[urlscan v2] cannot extract domain")
            return {}

        print("[urlscan v2] domain: " + domain)
        print("[urlscan v2] querying urlscan.io (free tier, no key)")

        data, status = _urlscan_search(domain, size=100)
        if status != "ok":
            print("[urlscan v2] API error: " + str(status)[:100])
            print("[urlscan v2] possible rate limit (100/day free). Skipping.")
            return {"domain": domain, "error": status}

        # urlsan может вернуть {"message": "..."} при ошибке
        if "results" not in data:
            msg = data.get("message", "no results field")
            print("[urlscan v2] unexpected response: " + str(msg)[:100])
            return {"domain": domain, "error": str(msg)[:100]}

        results = data.get("results", [])
        total = data.get("total", len(results))
        print("[urlscan v2] results: " + str(len(results)) + " (total=" + str(total) + ")")

        if not results:
            print("[urlscan v2] no scans found for this domain")
            return {"domain": domain, "ips": [], "urls": []}

        # === filter by recent 90 days ===
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        recent = []
        old_count = 0
        for res in results:
            t = _parse_time(res.get("task", {}).get("time"))
            if t and t < cutoff:
                old_count += 1
                continue
            recent.append(res)

        print("[urlscan v2] recent (<90d): " + str(len(recent)) + ", older: " + str(old_count))

        # === aggregate ===
        ips = set()
        domains = set()
        urls = set()
        asns = set()
        countries = set()
        servers = set()
        sensitive_urls = set()

        for res in recent:
            page = res.get("page", {}) or {}
            task = res.get("task", {}) or {}
            stats = res.get("stats", {}) or {}

            ip = page.get("ip", "")
            if ip:
                ips.add(ip)
            d = page.get("domain", "")
            if d:
                domains.add(d)
            u = page.get("url", "") or task.get("url", "")
            if u:
                urls.add(u)
                if _is_sensitive(u):
                    sensitive_urls.add(u)

            asn = page.get("asn", "")
            if asn:
                asns.add(str(asn))
            country = page.get("country", "")
            if country:
                countries.add(country)
            server = page.get("server", "")
            if server:
                servers.add(server)

        # === output ===
        print()
        print("[urlscan v2] unique:")
        print("  IPs: " + str(len(ips)))
        print("  domains: " + str(len(domains)))
        print("  URLs: " + str(len(urls)))
        print("  ASNs: " + str(len(asns)))
        print("  countries: " + str(len(countries)))
        if servers:
            print("  servers: " + str(list(servers)[:5]))

        if ips:
            print()
            print("[urlscan v2] IPs:")
            for ip in sorted(ips)[:15]:
                print("  " + ip)

        if domains:
            other_domains = sorted([d for d in domains if d != domain])
            if other_domains:
                print()
                print("[urlscan v2] related domains:")
                for d in other_domains[:15]:
                    print("  " + d)

        if sensitive_urls:
            print()
            print("[urlscan v2] sensitive URLs (" + str(len(sensitive_urls)) + "):")
            for u in sorted(sensitive_urls)[:20]:
                print("  " + u)

        # === findings ===
        findings_count = 0
        try:
            logger.finding("urlscan_summary", "info",
                           domain + ": " + str(len(recent)) + " recent scans, " +
                           str(len(ips)) + " IPs, " + str(len(domains)) + " domains")
            findings_count += 1

            for ip in sorted(ips)[:10]:
                logger.finding("urlscan_ip", "info", ip)
                findings_count += 1

            for d in sorted(domains):
                if d != domain:
                    logger.finding("urlscan_related_domain", "info", d)
                    findings_count += 1

            for u in sorted(sensitive_urls)[:15]:
                logger.finding("urlscan_sensitive", "medium", u)
                findings_count += 1
        except Exception:
            pass

        print()
        print("[urlscan v2] findings: " + str(findings_count))

        return {
            "domain": domain,
            "total_scans": total,
            "recent_scans": len(recent),
            "ips": sorted(ips),
            "domains": sorted(domains),
            "urls": sorted(urls)[:100],
            "sensitive_urls": sorted(sensitive_urls),
            "asns": sorted(asns),
            "countries": sorted(countries),
            "servers": sorted(servers),
        }
