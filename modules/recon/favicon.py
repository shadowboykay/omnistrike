"""favicon v2 — favicon hash (Shodan-style mmh3) + HTML parsing + known DB.

Что делает:
  1. Парсит HTML главной на <link rel="icon"> / shortcut icon / apple-touch-icon
  2. Fallback на типовые пути /favicon.ico, /favicon.png, ...
  3. Считает 3 хеша на каждый файл:
     - mmh3 signed int (Shodan fingerprint)
     - mmh3 unsigned hex
     - md5 (для других БД)
  4. Сверяет с known-favicon DB: Jira, Jenkins, GitLab, Grafana, etc.
  5. Возвращает hashes для Shodan query

mmh3 реализован на чистом Python (murmur3_32) — не требует зависимостей.
"""
import hashlib
import base64
import re
import struct
import json
from urllib.parse import urlparse, urljoin
from core.http import HttpClient


# ============================================================
# Pure-python murmur3_32 (совместим с mmh3.hash)
# ============================================================

def _mmh3_32(data, seed=0):
    """MurmurHash3 x86_32. Возвращает signed int (как mmh3.hash)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    roundedEnd = (length & 0xfffffffc)
    for i in range(0, roundedEnd, 4):
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
             ((data[i + 2] & 0xff) << 16) | (data[i + 3] & 0xff) << 24
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 = (data[roundedEnd + 2] & 0xff) << 16
    if val in (2, 3):
        k1 |= (data[roundedEnd + 1] & 0xff) << 8
    if val in (1, 2, 3):
        k1 |= data[roundedEnd] & 0xff
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)
    # signed
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def _shodan_hash(content):
    """Shodan favicon hash = mmh3.hash(base64.encodebytes(content))."""
    b64 = base64.encodebytes(content)
    try:
        import mmh3 as _mmh3_lib
        return _mmh3_lib.hash(b64)
    except ImportError:
        return _mmh3_32(b64)


# ============================================================
# Known favicon hashes (Shodan mmh3 signed int)
# ============================================================

KNOWN_FAVICONS = {
    # --- devops / infra ---
    116323821:  "Grafana",
    999357577:  "Grafana (older)",
    -1278323681: "Jenkins",
    -1702765738: "GitLab",
    1994480514:  "Jira",
    705869573:   "Confluence",
    1489921879:  "SonarQube",
    1848946384:  "Kibana",
    -1146810833: "Prometheus",
    988422529:   "Zabbix",
    -1441956789: "Nagios",
    -3950932:    "Rancher",
    -874047373:  "Portainer",
    1080840422:  "Splunk",
    -536724273:  "ELK",
    # --- CMS / apps ---
    -1200421188: "WordPress",
    1059516348:  "WordPress (alt)",
    708578229:   "Drupal",
    1409001605:  "Joomla",
    2063921195:  "phpMyAdmin",
    -1473343472: "cPanel",
    1174383373:  "Webmin",
    -1486190223: "Plesk",
    # --- frameworks ---
    1838417872:  "Spring Boot",
    -1725709697: "Django (admin)",
    -1684978925: "Flask",
    # --- services ---
    -872537684:  "RabbitMQ",
    1392243210:  "Redis Commander",
    568318524:   "Minio",
    -1978898747: "Apache Airflow",
    2005188066:  "MongoDB Compass",
    # --- security ---
    -1286393309: "Metasploit",
    1872573073:  "Burp Suite",
    -350487607:  "Kali",
    # --- network ---
    116323821:   "Grafana",
    1516141735:  "Mikrotik",
    -1142008167: "Cisco",
    -1719880617: "pfSense",
    -813311113:  "OpenWRT",
    # --- misc ---
    -1180350104: "Bitwarden",
    -1719412249: "Nextcloud",
    1270623461:  "Owncloud",
    -1965042486: "GitHub Enterprise",
}


# ============================================================
# Ссылки на favicon в HTML
# ============================================================

FAVICON_LINK_RE = re.compile(
    r'<link[^>]+rel=["\'](?:shortcut\s+icon|icon|apple-touch-icon(?:-precomposed)?)["\'][^>]*>',
    re.I | re.S
)

HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)


def _extract_favicon_links(html, base_url):
    """Извлекает URL'ы favicon из <link rel='icon'> тегов."""
    out = []
    for m in FAVICON_LINK_RE.finditer(html or ""):
        tag = m.group(0)
        href = HREF_RE.search(tag)
        if not href:
            continue
        raw = href.group(1).strip()
        if not raw or raw.startswith("data:"):
            continue
        # абсолютный URL
        full = urljoin(base_url, raw)
        if full not in out:
            out.append(full)
    return out


# ============================================================
# Модуль
# ============================================================

DEFAULT_PATHS = [
    "/favicon.ico",
    "/favicon.png",
    "/favicon.svg",
    "/apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png",
    "/static/favicon.ico",
    "/assets/favicon.ico",
    "/images/favicon.ico",
    "/img/favicon.ico",
]


class Favicon:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        # origin для urljoin
        u = urlparse(base)
        origin = u.scheme + "://" + u.netloc if u.scheme else base
        http = HttpClient(session, logger)

        print("[favicon v2] target: " + base)

        # --- 1. fetch main page, extract favicon links ---
        try:
            r_main = http.get(base)
            html = (r_main.text or "") if r_main else ""
        except Exception:
            html = ""

        from_html = _extract_favicon_links(html, origin)
        print("[favicon v2] links in HTML: " + str(len(from_html)))
        for link in from_html[:5]:
            print("  " + link)

        # --- 2. combine with default paths ---
        candidates = []
        for link in from_html:
            candidates.append(link)
        for p in DEFAULT_PATHS:
            candidates.append(origin + p)

        # dedupe
        seen = set()
        unique_candidates = []
        for c in candidates:
            if c in seen:
                continue
            seen.add(c)
            unique_candidates.append(c)

        print("[favicon v2] testing " + str(len(unique_candidates)) + " candidate URLs")

        out = []
        for url in unique_candidates:
            try:
                r = http.get(url, allow_redirects=True)
            except Exception:
                continue
            if not r or r.status_code != 200:
                continue
            content = r.content or b""
            if len(content) == 0:
                continue
            # проверка на бинарный favicon (ICO/PNG/SVG magic)
            is_icon = (
                content.startswith(b"\x00\x00\x01\x00") or  # ICO
                content.startswith(b"\x89PNG") or            # PNG
                content.startswith(b"<svg") or                # SVG
                content.startswith(b"<?xml") or               # SVG-as-XML
                content.startswith(b"GIF8")                   # GIF
            )
            if not is_icon:
                # не favicon (HTML 404-страница с кодом 200)
                continue

            mmh3 = _shodan_hash(content)
            md5 = hashlib.md5(content).hexdigest()
            sha256 = hashlib.sha256(content).hexdigest()
            size = len(content)

            match = KNOWN_FAVICONS.get(mmh3)
            marker = " [" + match + "]" if match else ""

            print("  [+] " + url)
            print("      size=" + str(size) + " mmh3=" + str(mmh3) + marker)
            print("      md5=" + md5 + " sha256=" + sha256[:16] + "...")

            entry = {
                "url": url,
                "size": size,
                "mmh3": mmh3,
                "md5": md5,
                "sha256": sha256,
                "matched": match,
            }
            out.append(entry)

            # findings
            try:
                if match:
                    logger.finding("favicon_match", "medium",
                                   url + " matches " + match + " (mmh3=" + str(mmh3) + ")")
                else:
                    logger.finding("favicon_hash", "info",
                                   url + " mmh3=" + str(mmh3) + " size=" + str(size))
            except Exception:
                pass

        print()
        print("[favicon v2] found " + str(len(out)) + " valid favicons")
        if out:
            print("[favicon v2] Shodan query: http.favicon.hash:<mmh3>")
            for e in out[:3]:
                print("  " + str(e["mmh3"]) + " -> " + e["url"])

        return {
            "favicons": out,
            "html_links": from_html,
        }
