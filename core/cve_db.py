# core/cve_db.py — CVE database: NVD + KEV + EPSS + GHSA + Exploit-DB
import json, time, os, gzip
from pathlib import Path
import requests

DATA_DIR = Path(__file__).parent.parent / "data" / "cve"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Sources
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
GHSA_URL = "https://api.github.com/advisories"
EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

CACHE_NVD = DATA_DIR / "nvd_cache.json"
CACHE_KEV = DATA_DIR / "kev.json"
CACHE_EPSS = DATA_DIR / "epss.json"
CACHE_GHSA = DATA_DIR / "ghsa.json"
CACHE_EDB = DATA_DIR / "exploitdb.json"


def fetch(url, timeout=30, headers=None, params=None):
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers=headers or {}, params=params or {})
        if r.status_code == 200:
            return r
    except Exception:
        pass
    return None


# ============ KEV (Known Exploited Vulnerabilities) ============

def update_kev():
    r = fetch(KEV_URL, timeout=60)
    if not r:
        print("  ✗ KEV: fetch failed")
        return {}
    try:
        data = r.json()
        vulns = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        CACHE_KEV.write_text(json.dumps(vulns, indent=2))
        print(f"  ✓ KEV: {len(vulns)} exploited CVEs cached")
        return vulns
    except Exception as e:
        print(f"  ✗ KEV: {e}")
        return {}


def load_kev():
    if CACHE_KEV.is_file():
        try:
            return json.loads(CACHE_KEV.read_text())
        except Exception:
            pass
    return {}


# ============ NVD ============

def query_nvd(keyword=None, cpe=None, days=None, limit=100, severity=None):
    params = {"resultsPerPage": min(limit, 2000)}
    if keyword: params["keywordSearch"] = keyword
    if cpe: params["cpeName"] = cpe
    if severity: params["cvssV3Severity"] = severity.upper()
    if days:
        end = time.strftime("%Y-%m-%dT%H:%M:%S.000")
        start = time.strftime("%Y-%m-%dT%H:%M:%S.000",
                              time.localtime(time.time() - days * 86400))
        params["lastModStartDate"] = start
        params["lastModEndDate"] = end
    r = fetch(NVD_API, timeout=30, params=params,
              headers={"User-Agent": "omnistrike/1.0", "apiKey": os.environ.get("NVD_KEY", "")})
    if not r:
        return []
    try:
        return r.json().get("vulnerabilities", [])
    except Exception:
        return []


def parse_cve(item):
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    metrics = cve.get("metrics", {})
    score, severity, vector = 0.0, "unknown", ""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            score = m.get("baseScore", 0)
            severity = m.get("baseSeverity", severity).lower()
            vector = m.get("vectorString", "")
            break
    cpes = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    cpes.append(m.get("criteria", ""))
    refs = [r.get("url", "") for r in cve.get("references", [])][:5]
    return {
        "id": cve_id, "description": desc[:300], "score": score,
        "severity": severity, "vector": vector, "cpes": cpes,
        "published": cve.get("published", ""), "refs": refs,
    }


# ============ EPSS ============

def enrich_epss(cve_id):
    r = fetch(f"{EPSS_URL}?cve={cve_id}", timeout=15)
    if r:
        try:
            data = r.json().get("data", [])
            if data:
                return {"epss": float(data[0].get("epss", 0)),
                        "epss_percentile": float(data[0].get("percentile", 0))}
        except Exception:
            pass
    return {}


# ============ GHSA (GitHub Security Advisories) ============

def update_ghsa(limit=2000):
    r = fetch(GHSA_URL, timeout=60, params={"per_page": 100},
              headers={"Accept": "application/vnd.github+json",
                       "User-Agent": "omnistrike/1.0"})
    if not r:
        print("  ✗ GHSA: fetch failed")
        return {}
    try:
        data = r.json()
        advisories = {}
        for a in data:
            cve = a.get("cve_id")
            if cve:
                advisories[cve] = {
                    "ghsa_id": a.get("ghsa_id"),
                    "summary": a.get("summary", ""),
                    "severity": a.get("severity", ""),
                    "cvss": a.get("cvss", {}).get("score", 0),
                    "ecosystem": a.get("vulnerabilities", [{}])[0].get("package", {}).get("ecosystem", "") if a.get("vulnerabilities") else "",
                    "published": a.get("published_at", ""),
                }
        CACHE_GHSA.write_text(json.dumps(advisories, indent=2))
        print(f"  ✓ GHSA: {len(advisories)} advisories cached")
        return advisories
    except Exception as e:
        print(f"  ✗ GHSA: {e}")
        return {}


def load_ghsa():
    if CACHE_GHSA.is_file():
        try:
            return json.loads(CACHE_GHSA.read_text())
        except Exception:
            pass
    return {}


# ============ Exploit-DB ============

def update_exploitdb():
    r = fetch(EXPLOITDB_URL, timeout=60)
    if not r:
        print("  ✗ ExploitDB: fetch failed")
        return {}
    try:
        import csv
        from io import StringIO
        reader = csv.DictReader(StringIO(r.text))
        db = {}
        for row in reader:
            edb_id = row.get("id")
            cve = row.get("codes", "")
            if cve and cve.startswith("CVE-"):
                for c in cve.split(";"):
                    c = c.strip()
                    if c.startswith("CVE-"):
                        if c not in db:
                            db[c] = []
                        db[c].append({
                            "edb_id": edb_id,
                            "title": row.get("description", "")[:100],
                            "type": row.get("type", ""),
                            "platform": row.get("platform", ""),
                            "date": row.get("date", ""),
                        })
        CACHE_EDB.write_text(json.dumps(db, indent=2))
        print(f"  ✓ ExploitDB: {len(db)} CVEs with exploits cached")
        return db
    except Exception as e:
        print(f"  ✗ ExploitDB: {e}")
        return {}


def load_edb():
    if CACHE_EDB.is_file():
        try:
            return json.loads(CACHE_EDB.read_text())
        except Exception:
            pass
    return {}


# ============ Unified enrichment ============

def enrich(cve_id):
    """Add KEV + EPSS + GHSA + ExploitDB info to a CVE."""
    info = {}
    kev = load_kev()
    if cve_id in kev:
        info["kev"] = True
        info["kev_added"] = kev[cve_id].get("dateAdded", "")
        info["kev_ransomware"] = kev[cve_id].get("knownRansomwareCampaignUse", "Unknown")
    else:
        info["kev"] = False

    info.update(enrich_epss(cve_id))

    ghsa = load_ghsa()
    if cve_id in ghsa:
        info["ghsa"] = ghsa[cve_id].get("ghsa_id", "")
        info["ghsa_summary"] = ghsa[cve_id].get("summary", "")[:150]

    edb = load_edb()
    if cve_id in edb:
        info["exploits"] = edb[cve_id]
        info["exploits_count"] = len(edb[cve_id])

    return info


def update_all():
    print("[cve_db] updating all sources...")
    total = {}
    total["kev"] = len(update_kev())
    total["ghsa"] = len(update_ghsa())
    total["exploitdb"] = len(update_exploitdb())
    print(f"[cve_db] done. cached: {total}")
    return total


if __name__ == "__main__":
    update_all()
