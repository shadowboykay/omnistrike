"""crt_sh v2 — subdomain discovery via certificate transparency.

Источники (по порядку):
  1. crt.sh (primary, JSON API без ключа)
  2. certspotter (fallback)

Фильтры:
  - name == domain или name.endswith(".domain")
  - wildcard (*.example.com) сохраняется как отдельный маркер
  - мусор (@email, невалидные хосты) отсеивается
  - дубликаты убираются
  - sort: по частоте появления в сертификатах

Опционально: DNS verify через DoH (только для топ-30).
"""
import json
import socket
import urllib.request
import urllib.parse
import re
from collections import Counter


CRT_SH_URL = "https://crt.sh/?q={q}&output=json"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names"


VALID_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,62}[a-z0-9])?)*$")


def _extract_host(target):
    if "://" in target:
        u = urllib.parse.urlparse(target)
        return u.hostname or ""
    return target.split("/")[0].split(":")[0]


def _is_valid_host(name):
    if not name or len(name) > 253:
        return False
    if "@" in name or " " in name or "_" in name:
        return False
    return bool(VALID_HOST_RE.match(name.lower()))


def _belongs_to_domain(name, domain):
    n = name.lower().lstrip("*.").rstrip(".")
    d = domain.lower()
    return n == d or n.endswith("." + d)


def _fetch_crt_sh(domain, timeout=15):
    """Первичный источник. Возвращает list of dicts или []."""
    url = CRT_SH_URL.format(q=urllib.parse.quote("%." + domain))
    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (compatible; OmniStrike/2.0)",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="ignore")
        if not body.strip():
            return []
        # защита от HTML вместо JSON
        if body.lstrip().startswith("<"):
            return []
        return json.loads(body)
    except Exception:
        return []


def _fetch_certspotter(domain, timeout=15):
    """Fallback источник. Возвращает list of dicts или []."""
    url = CERTSPOTTER_URL.format(d=urllib.parse.quote(domain))
    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (compatible; OmniStrike/2.0)",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="ignore")
        if not body.strip():
            return []
        return json.loads(body)
    except Exception:
        return []


def _doh_resolve(host, timeout=5):
    """A-запись через Cloudflare DoH. True если резолвится."""
    try:
        url = "https://cloudflare-dns.com/dns-query?name=" + host + "&type=A"
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        return data.get("Status") == 0 and bool(data.get("Answer"))
    except Exception:
        return False


def _extract_names_from_crt_sh(entries, domain):
    """Извлекает имена из crt.sh entries."""
    counter = Counter()
    for e in entries or []:
        for field in ("name_value", "common_name"):
            raw = e.get(field, "")
            if not raw:
                continue
            for name in str(raw).split("\n"):
                name = name.strip().lower().rstrip(".")
                if not _belongs_to_domain(name, domain):
                    continue
                if not _is_valid_host(name.lstrip("*.")):
                    continue
                counter[name] += 1
    return counter


def _extract_names_from_certspotter(entries, domain):
    """Извлекает имена из certspotter entries."""
    counter = Counter()
    for e in entries or []:
        dns_names = e.get("dns_names", [])
        if not isinstance(dns_names, list):
            continue
        for name in dns_names:
            if not isinstance(name, str):
                continue
            name = name.strip().lower().rstrip(".")
            if not _belongs_to_domain(name, domain):
                continue
            if not _is_valid_host(name.lstrip("*.")):
                continue
            counter[name] += 1
    return counter


class CrtSh:
    def run(self, session, logger):
        domain = _extract_host(session.target)
        if not domain:
            print("[crt_sh v2] cannot extract domain")
            return {"subdomains": []}

        print("[crt_sh v2] domain: " + domain)
        print("[crt_sh v2] source: crt.sh (primary)")

        # --- Primary: crt.sh ---
        entries = _fetch_crt_sh(domain)
        source = "crt.sh"
        counter = _extract_names_from_crt_sh(entries, domain)

        # --- Fallback: certspotter ---
        if not counter:
            print("[crt_sh v2] crt.sh empty — falling back to certspotter")
            entries2 = _fetch_certspotter(domain)
            if entries2:
                source = "certspotter"
                counter = _extract_names_from_certspotter(entries2, domain)

        if not counter:
            print("[crt_sh v2] no subdomains found (rate-limit or no CT entries)")
            return {"domain": domain, "subdomains": []}

        # --- sort by frequency ---
        # популярные (в нескольких сертификатах) — более "живые"
        sorted_names = [name for name, _ in counter.most_common()]

        # --- DNS verify top-N through DoH ---
        print()
        print("[crt_sh v2] DNS verify (top 30 via Cloudflare DoH):")
        verified = []
        for name in sorted_names[:30]:
            if _doh_resolve(name):
                verified.append(name)
                print("  [live] " + name)
        unverified_count = len(sorted_names) - len(verified)

        # --- print summary ---
        print()
        print("[crt_sh v2] found " + str(len(sorted_names)) + " unique names")
        print("[crt_sh v2] live (top 30 tested): " + str(len(verified)))
        print("[crt_sh v2] source: " + source)

        # --- full list (top 100) ---
        print()
        print("[crt_sh v2] first 100:")
        for i, name in enumerate(sorted_names[:100], 1):
            freq = counter[name]
            marker = " [live]" if name in verified else ""
            print("  " + str(i) + ". " + name + " (" + str(freq) + "x)" + marker)
        if len(sorted_names) > 100:
            print("  ... and " + str(len(sorted_names) - 100) + " more")

        # --- findings ---
        # одно info finding со summary, не 100 отдельных
        try:
            logger.finding("crt_sh_summary", "info",
                           domain + ": " + str(len(sorted_names)) + " names, " +
                           str(len(verified)) + " live, source=" + source)
            # отдельные findings только для live
            for name in verified:
                logger.finding("subdomain_ct_live", "info", name)
        except Exception:
            pass

        return {
            "domain": domain,
            "subdomains": sorted_names,
            "verified": verified,
            "unverified_count": unverified_count,
            "source": source,
        }
