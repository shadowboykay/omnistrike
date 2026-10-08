"""shodan_query v2 — InternetDB (free, no key) + optional Shodan API.

Primary: InternetDB (https://internetdb.shodan.io/<ip>) — без ключа:
  - open ports
  - CPE (versions → CVE matching)
  - hostnames
  - tags (cdn, eol-os, self-signed, cloud, ...)
  - vulns (CVE list)

Fallback: Shodan API with SHODAN_KEY env for full banner data.
"""
import os
import json
import urllib.request
import urllib.parse


INTERNETDB = "https://internetdb.shodan.io/"
SHODAN_API = "https://api.shodan.io/shodan/host/"


def _extract_host(target):
    if "://" in target:
        u = urllib.parse.urlparse(target)
        return u.hostname or ""
    return target.split("/")[0].split(":")[0]


def _doh_resolve(host, timeout=6):
    try:
        url = "https://cloudflare-dns.com/dns-query?name=" + host + "&type=A"
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        if data.get("Status") != 0:
            return []
        return [a.get("data") for a in data.get("Answer", []) if a.get("type") == 1]
    except Exception:
        return []


def _internetdb(ip, timeout=8):
    """InternetDB query. Returns dict или {}."""
    try:
        url = INTERNETDB + ip
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="ignore")
        if not body.strip():
            return {}
        data = json.loads(body)
        if isinstance(data, dict) and "detail" in data:
            # {"detail":"No information available"}
            return {}
        return data
    except Exception:
        return {}


def _shodan_api(ip, key, timeout=10):
    """Full Shodan API query."""
    try:
        url = SHODAN_API + ip + "?key=" + urllib.parse.quote(key)
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return {}


def _severity_for_cve(cve_id):
    """Грубая severity из ID (без базы EPSS)."""
    return "high"


class ShodanQuery:
    def run(self, session, logger):
        target = session.target
        host = _extract_host(target)
        if not host:
            print("[shodan v2] cannot extract host")
            return {}

        print("[shodan v2] target: " + target)
        print("[shodan v2] host: " + host)

        # resolve to IP
        if host.replace(".", "").isdigit():
            ips = [host]
        else:
            ips = _doh_resolve(host)
            if not ips:
                try:
                    import socket
                    ips = [socket.gethostbyname(host)]
                except Exception:
                    pass

        if not ips:
            print("[shodan v2] cannot resolve host")
            return {"error": "no_resolve"}

        print("[shodan v2] resolved: " + ", ".join(ips[:5]))
        print()

        key = os.environ.get("SHODAN_KEY", "")
        use_api = bool(key)
        if use_api:
            print("[shodan v2] SHODAN_KEY present — using full API")
        else:
            print("[shodan v2] SHODAN_KEY not set — using InternetDB (free)")

        findings_count = 0
        out = {"host": host, "ips": [], "findings_count": 0}

        for ip in ips[:3]:
            print()
            print("[shodan v2] ======== IP: " + ip + " ========")

            record = {"ip": ip}

            if use_api:
                data = _shodan_api(ip, key)
                if data:
                    ports = data.get("ports", [])
                    org = data.get("org", "")
                    country = data.get("country_name", "")
                    os_ = data.get("os", "")
                    vulns = list((data.get("vulns") or {}).keys())
                    hostnames = data.get("hostnames", [])
                    tags = data.get("tags", [])

                    print("  org: " + str(org))
                    print("  country: " + str(country))
                    print("  os: " + str(os_))
                    print("  ports: " + str(ports))
                    print("  hostnames: " + str(hostnames))
                    print("  tags: " + str(tags))
                    if vulns:
                        print("  CVEs: " + str(len(vulns)))

                    record.update({
                        "source": "shodan_api",
                        "org": org, "country": country, "os": os_,
                        "ports": ports, "hostnames": hostnames, "tags": tags,
                        "vulns": vulns,
                    })

                    # findings по CVEs
                    for cve in vulns[:20]:
                        sev = _severity_for_cve(cve)
                        try:
                            logger.finding("shodan_cve", sev, ip + " " + cve)
                            findings_count += 1
                        except Exception:
                            pass
                continue

            # === InternetDB ===
            data = _internetdb(ip)
            if not data:
                print("  no data (IP не в InternetDB)")
                record["source"] = "internetdb"
                record["empty"] = True
                out["ips"].append(record)
                continue

            ports = data.get("ports", []) or []
            hostnames = data.get("hostnames", []) or []
            tags = data.get("tags", []) or []
            cpes = data.get("cpes", []) or []
            vulns = data.get("vulns", []) or []

            print("  ports: " + str(ports))
            print("  hostnames: " + str(hostnames[:10]))
            print("  tags: " + str(tags))
            print("  cpes: " + str(len(cpes)) + " products")
            for c in cpes[:8]:
                print("    " + c)
            if vulns:
                print("  CVEs: " + str(len(vulns)))
                for v in vulns[:10]:
                    print("    " + v)

            record.update({
                "source": "internetdb",
                "ports": ports,
                "hostnames": hostnames,
                "tags": tags,
                "cpes": cpes,
                "vulns": vulns,
            })

            # findings
            try:
                if ports:
                    logger.finding("shodan_ports", "info",
                                   ip + " ports: " + ",".join(str(p) for p in ports[:10]))
                    findings_count += 1
                if tags:
                    logger.finding("shodan_tags", "info",
                                   ip + " tags: " + ",".join(tags))
                    findings_count += 1
                for cve in vulns[:20]:
                    logger.finding("shodan_cve", "high", ip + " " + cve)
                    findings_count += 1
            except Exception:
                pass

            out["ips"].append(record)

        out["findings_count"] = findings_count
        print()
        print("[shodan v2] findings: " + str(findings_count))
        return out
