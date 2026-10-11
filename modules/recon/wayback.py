"""wayback v2 — archive.org CDX + исторические URL + sensitive path mining.

Что делает:
  1. HTTPS CDX API (retry, rate-limit aware)
  2. Поля: original, timestamp, statuscode, mimetype, digest
  3. Фильтр statuscode=200 (v1 собирал 404-мусор)
  4. Dedup по нормализованному пути
  5. Sensitive mining: 30+ категорий (secrets/backups/admin/old_api/configs)
  6. Отсев статики (js/css/img/font) — не интересно
  7. Сохранение уникальных путей в reports/wayback_<domain>.txt
     для подсева dir_brute/subdomain_brute
  8. Findings: grouped (medium для secrets/backups, low для остального)
"""
import re
import json
import os
import urllib.request
import urllib.parse
from collections import defaultdict
from urllib.parse import urlparse
from core.http import HttpClient


CDX_API = "https://web.archive.org/cdx/search/cdx"

# поля CDX
CDX_FIELDS = "original,timestamp,statuscode,mimetype,digest"

# чувствительные ключи с категориями
SENSITIVE_CATEGORIES = {
    "secrets": [
        ".env", ".git/", ".svn/", ".hg/", ".DS_Store",
        "id_rsa", "id_dsa", ".ssh/", "credentials",
        "secret", "password", "passwd", "token", "apikey", "api_key",
        "private_key", ".pem", ".key", ".pfx", ".p12",
    ],
    "backups": [
        "backup", ".bak", ".old", ".orig", ".save", ".swp", ".tmp",
        ".sql", ".sql.gz", ".dump", ".tar", ".tar.gz", ".tgz", ".zip", ".rar", ".7z",
        "db.sql", "database.sql", "dump.sql",
    ],
    "admin": [
        "/admin", "/administrator", "/wp-admin", "/wp-login",
        "/manager", "/console", "/cpanel", "/webmin", "/phpmyadmin",
        "/pma/", "/adminer", "/jenkins", "/gitlab", "/sonar",
    ],
    "configs": [
        "config.", "settings.", "web.config", ".htaccess", ".htpasswd",
        "wp-config", "database.yml", "docker-compose", ".dockerignore",
        "phpinfo.php", "info.php", "test.php",
    ],
    "old_api": [
        "/api/v0/", "/api/v1/", "/api/v2/", "/api/old/",
        "/rest/", "/xmlrpc.php", "/soap/",
        "/graphql/playground", "/graphiql",
    ],
    "dev": [
        "/dev/", "/test/", "/staging/", "/qa/", "/beta/", "/demo/",
        "/debug", "/trace", "/actuator", "/env/", "/metrics",
    ],
}

# статика — не интересно
STATIC_EXT = re.compile(
    r"\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|webp|avif|map|mp4|mp3|pdf|docx?|xlsx?|pptx?)(?:\?|$)",
    re.I
)

# классификация
def _classify(url):
    low = url.lower()
    for cat, keys in SENSITIVE_CATEGORIES.items():
        for k in keys:
            if k in low:
                return cat
    return None


def _normalize_path(url):
    """Нормализует URL: убирает query+фрагмент для dedup-ключа."""
    try:
        u = urlparse(url)
        return u.netloc + u.path
    except Exception:
        return url


def _cdx_query(domain, limit=5000, timeout=25, http_client=None):
    """CDX API query с retry."""
    params = {
        "url": "*." + domain + "/*",
        "output": "json",
        "collapse": "urlkey",
        "limit": str(limit),
        "fl": CDX_FIELDS,
    }
    url = CDX_API + "?" + urllib.parse.urlencode(params)
    for attempt in range(2):
        try:
            if http_client is not None:
                _r = http_client.get(url)
                if not _r or _r.status_code != 200:
                    return []
                body = _r.text or ""
            else:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (compatible; OmniStrike/2.0)",
                    "Accept": "application/json",
                })
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    body = r.read().decode("utf-8", errors="ignore")
            if not body.strip():
                return []
            if body.lstrip().startswith("<"):
                return []
            data = json.loads(body)
            if not isinstance(data, list) or len(data) < 2:
                return []
            return data[1:]  # skip header row
        except Exception:
            if attempt == 0:
                continue
            return []
    return []


class Wayback:
    def run(self, session, logger):
        target = session.target
        # извлекаем домен
        if "://" in target:
            u = urlparse(target)
            domain = u.hostname or ""
        else:
            domain = target.split("/")[0].split(":")[0]

        if not domain:
            print("[wayback v2] cannot extract domain")
            return {"urls": []}

        print("[wayback v2] domain: " + domain)
        print("[wayback v2] querying CDX API (limit 5000)...")

        http = HttpClient(session, logger)
        rows = _cdx_query(domain, limit=5000, http_client=http)
        if not rows:
            print("[wayback v2] no CDX data (empty or rate-limited)")
            return {"domain": domain, "urls": []}

        print("[wayback v2] raw rows: " + str(len(rows)))

        # === parse ===
        all_urls = []
        seen_normpaths = set()
        interesting_by_cat = defaultdict(list)
        static_count = 0
        non_200_count = 0

        for row in rows:
            if len(row) < 5:
                continue
            url_ = str(row[0])
            timestamp = str(row[1])
            statuscode = str(row[2])
            mimetype = str(row[3])
            digest = str(row[4])

            # фильтр не-200
            if statuscode and statuscode != "200":
                non_200_count += 1
                continue

            # dedup по нормализованному пути
            norm = _normalize_path(url_)
            if norm in seen_normpaths:
                continue
            seen_normpaths.add(norm)

            entry = {
                "url": url_,
                "timestamp": timestamp,
                "status": statuscode,
                "mimetype": mimetype,
                "digest": digest,
            }
            all_urls.append(entry)

            # фильтр статики — не считаем interesting
            if STATIC_EXT.search(url_):
                static_count += 1
                continue

            cat = _classify(url_)
            if cat:
                interesting_by_cat[cat].append(entry)

        total_unique = len(all_urls)
        print("[wayback v2] unique URLs (200 only): " + str(total_unique))
        print("[wayback v2] static filtered: " + str(static_count))
        print("[wayback v2] non-200 filtered: " + str(non_200_count))

        # === output by category ===
        print()
        print("[wayback v2] interesting paths by category:")
        for cat in sorted(interesting_by_cat.keys()):
            items = interesting_by_cat[cat]
            print("  " + cat + ": " + str(len(items)) + " URLs")
            for e in items[:5]:
                print("    " + e["url"][:120])
            if len(items) > 5:
                print("    ... and " + str(len(items) - 5) + " more")

        # === save unique paths to file for other modules ===
        out_dir = "reports"
        os.makedirs(out_dir, exist_ok=True)
        out_file = out_dir + "/wayback_" + re.sub(r"[^a-z0-9.-]", "_", domain.lower()) + ".txt"
        unique_paths = set()
        for e in all_urls:
            try:
                u = urlparse(e["url"])
                if u.path and u.path != "/":
                    unique_paths.add(u.path)
            except Exception:
                pass

        try:
            with open(out_file, "w") as f:
                for p in sorted(unique_paths):
                    f.write(p + "\n")
            print()
            print("[wayback v2] saved " + str(len(unique_paths)) + " unique paths → " + out_file)
        except Exception as ex:
            print("[wayback v2] cannot save paths: " + str(ex))

        # === findings ===
        findings_count = 0
        try:
            logger.finding("wayback_summary", "info",
                           domain + ": " + str(total_unique) + " unique URLs, " +
                           str(len(interesting_by_cat)) + " interesting categories")
            findings_count += 1

            # medium для secrets/backups/admin
            for cat in ("secrets", "backups", "admin", "configs"):
                for e in interesting_by_cat.get(cat, [])[:15]:
                    logger.finding("wayback_" + cat, "medium", e["url"])
                    findings_count += 1

            # low для old_api/dev
            for cat in ("old_api", "dev"):
                for e in interesting_by_cat.get(cat, [])[:10]:
                    logger.finding("wayback_" + cat, "low", e["url"])
                    findings_count += 1
        except Exception:
            pass

        print()
        print("[wayback v2] findings: " + str(findings_count))

        return {
            "domain": domain,
            "total": total_unique,
            "static_filtered": static_count,
            "non_200_filtered": non_200_count,
            "interesting": {k: [e["url"] for e in v] for k, v in interesting_by_cat.items()},
            "urls": [e["url"] for e in all_urls[:2000]],
            "paths_file": out_file,
        }
