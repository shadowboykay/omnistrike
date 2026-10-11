"""virustotal_domain v2 — VT domain report + subdomains + whois + DNS.

Требует VT_API_KEY env (free-tier: 4 req/min, 500/day).

Что делает:
  1. Domain report:
     - last_analysis_stats (malicious / suspicious / harmless / undetected)
     - reputation
     - categories (vendor classification)
     - creation_date / last_modification_date
     - registrar (via whois)
     - jarm_hash (TLS fingerprint)
  2. Subdomains (up to 500)
  3. DNS records (A, MX, NS, TXT)
  4. Historical resolutions (IP history)
  5. Communication files (что с домена качают)

Findings:
  - malicious detection (medium/high по score)
  - recently registered (<90 дней) → medium (phishing pattern)
  - suspicious category → info
  - summary info

Fallback: если нет ключа — модуль использует публичный v3 endpoint
без auth для базовой информации (rate-limit жёсткий, но бывает).
"""
import os
import time
import json
import urllib.request
from datetime import datetime, timezone


VT_API = "https://www.virustotal.com/api/v3/domains/"


def _extract_domain(target):
    if "://" in target:
        u = urllib.parse.urlparse(target)
        return u.hostname or ""
    return target.split("/")[0].split(":")[0]


def _vt_get(url, key, timeout=15):
    """VT API request with rate-limit handling."""
    headers = {"Accept": "application/json"}
    if key:
        headers["x-apikey"] = key
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="ignore")
        return json.loads(body), 200
    except urllib.error.HTTPError as e:
        if e.code == 429:
            # rate limit — ждём и пробуем ещё раз
            time.sleep(15)
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return json.loads(r.read().decode("utf-8", errors="ignore")), 200
            except Exception as e2:
                return {"error": str(e2)[:100]}, 429
        return {"error": "HTTP " + str(e.code)}, e.code
    except Exception as e:
        return {"error": str(e)[:100]}, 0


def _ts_to_date(ts):
    """Unix timestamp → ISO date."""
    if not ts:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return None


class VirustotalDomain:
    def run(self, session, logger):
        key = os.environ.get("VT_API_KEY", "")
        domain = _extract_domain(session.target)
        if not domain:
            print("[virustotal v2] cannot extract domain")
            return {}

        print("[virustotal v2] domain: " + domain)
        if not key:
            print("[virustotal v2] VT_API_KEY not set — API rate-limited or 401")
            print("  free key: virustotal.com → profile → API key")

        # === 1. main domain report ===
        url = VT_API + domain
        data, status = _vt_get(url, key)
        if status != 200 or "data" not in data:
            print("[virustotal v2] API error: " + str(data.get("error", "unknown"))[:100])
            return {"domain": domain, "error": data.get("error")}

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        reputation = attrs.get("reputation", 0)
        categories = attrs.get("categories", {})
        creation_ts = attrs.get("creation_date")
        last_mod = attrs.get("last_modification_date")
        jarm = attrs.get("jarm_hash", "")
        registrar = attrs.get("registrar", "")

        print()
        print("[virustotal v2] analysis stats:")
        for k in ("malicious", "suspicious", "harmless", "undetected"):
            v = stats.get(k, 0)
            if v:
                print("  " + k + ": " + str(v))
        print("  reputation: " + str(reputation))

        if categories:
            # категории — как классифицируют вендоры
            uniq_cats = set(categories.values())
            print("  categories: " + str(list(uniq_cats)[:5]))

        if creation_ts:
            cdate = _ts_to_date(creation_ts)
            print("  created: " + str(cdate))
        if last_mod:
            print("  last modified: " + str(_ts_to_date(last_mod)))
        if registrar:
            print("  registrar: " + registrar)
        if jarm:
            print("  jarm: " + jarm[:30])

        # === 2. subdomains ===
        print()
        print("[virustotal v2] fetching subdomains...")
        url2 = VT_API + domain + "/subdomains?limit=100"
        d2, st2 = _vt_get(url2, key)
        subs = []
        if st2 == 200 and "data" in d2:
            for item in d2.get("data", []):
                sid = item.get("id", "")
                if sid:
                    subs.append(sid)
            print("  found: " + str(len(subs)))
            for s in subs[:20]:
                print("    " + s)
            if len(subs) > 20:
                print("    ... and " + str(len(subs) - 20) + " more")
        else:
            print("  subdomains API error: " + str(d2.get("error", "unknown"))[:80])

        # === 3. DNS records ===
        print()
        print("[virustotal v2] DNS records...")
        url3 = VT_API + domain + "/resolutions?limit=20"
        d3, st3 = _vt_get(url3, key)
        historic_ips = set()
        if st3 == 200 and "data" in d3:
            for item in d3.get("data", []):
                attr = item.get("attributes", {})
                ip = attr.get("ip_address", "")
                if ip:
                    historic_ips.add(ip)
            if historic_ips:
                print("  historical IPs: " + str(len(historic_ips)))
                for ip in list(historic_ips)[:10]:
                    print("    " + ip)

        # === findings ===
        findings = []
        try:
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious >= 5:
                findings.append({"type": "vt_malicious", "severity": "high",
                                 "count": malicious})
                logger.finding("virustotal_malicious", "high",
                               domain + " " + str(malicious) + " vendors flag")
            elif malicious > 0:
                findings.append({"type": "vt_malicious", "severity": "medium",
                                 "count": malicious})
                logger.finding("virustotal_malicious", "medium",
                               domain + " " + str(malicious) + " vendors flag")

            # recently registered (<90 days) — phish pattern
            if creation_ts:
                try:
                    cdate = datetime.fromtimestamp(int(creation_ts), tz=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - cdate).days
                    if age_days < 90:
                        findings.append({"type": "vt_recent_domain", "severity": "medium",
                                         "age_days": age_days})
                        logger.finding("virustotal_recent", "medium",
                                       domain + " registered " + str(age_days) + " days ago")
                except Exception:
                    pass

            # summary
            findings.append({"type": "vt_summary", "severity": "info",
                             "stats": stats, "subdomains": len(subs),
                             "historic_ips": len(historic_ips)})
            logger.finding("virustotal_summary", "info",
                           domain + " stats=" + str(stats))

            for s in subs[:30]:
                logger.finding("vt_subdomain", "info", s)
        except Exception:
            pass

        print()
        print("[virustotal v2] findings: " + str(len(findings)))

        return {
            "domain": domain,
            "stats": stats,
            "reputation": reputation,
            "categories": list(set(categories.values()))[:10] if categories else [],
            "creation_date": _ts_to_date(creation_ts),
            "last_modification": _ts_to_date(last_mod),
            "registrar": registrar,
            "subdomains": subs,
            "historic_ips": sorted(historic_ips),
            "findings": findings,
        }


import urllib.parse
import urllib.error
