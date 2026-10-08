"""sitemap v2 — sitemap.xml/gz/txt + sitemap_index recursion + sensitive detection.

Что делает:
  1. Пробует 8 путей: /sitemap.xml, /sitemap_index.xml, /sitemap-index.xml,
     /sitemap.xml.gz, /sitemap.txt, /sitemap/, /sitemap/sitemap.xml, /sm.xml
  2. Formats: XML (loc regex), GZ (gzip decode → XML), TXT (URL per line)
  3. sitemap_index: рекурсия до 2 уровней, с visited-set (защита от петель)
  4. Fallback: Sitemap: директивы из robots.txt
  5. Sensitive path detection: admin/backup/config/api/private/db/env
  6. Findings: summary (info), sensitive (medium), sitemap_gz (info)
"""
import re
import gzip
import secrets
from urllib.parse import urlparse
from core.http import HttpClient


PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/sitemap.xml.gz",
    "/sitemap.txt",
    "/sitemap/",
    "/sitemap/sitemap.xml",
    "/sm.xml",
]

# XML loc
RE_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I | re.S)
# robots.txt Sitemap: directive
RE_SITEMAP_DIRECTIVE = re.compile(r"^\s*Sitemap:\s*(\S+)", re.I | re.M)
# URL line in .txt sitemap
RE_TXT_URL = re.compile(r"^https?://\S+$", re.M)

# sensitive keywords в URL
SENSITIVE_KEYS = [
    "admin", "backup", "config", "private", "api/", "db", "secret",
    "dump", "test", "dev", "staging", "internal", "env",
    ".git", ".env", "phpmyadmin", "wp-admin", "shell", "upload",
    "debug", "console", "swagger", "actuator", "phpinfo",
]


def _is_sensitive(url):
    low = url.lower()
    return any(k in low for k in SENSITIVE_KEYS)


def _extract_urls(text, is_gz=False, is_txt=False):
    """Извлекает URL из sitemap body."""
    if not text:
        return []
    if is_txt:
        # plain text — один URL на строку
        return [u.strip() for u in RE_TXT_URL.findall(text) if u.strip()]
    # XML
    return RE_LOC.findall(text)


def _try_gzip(content):
    """Пробует распаковать gzip. Возвращает str или None."""
    try:
        return gzip.decompress(content).decode("utf-8", errors="ignore")
    except Exception:
        return None


class Sitemap:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        u = urlparse(base)
        origin = u.scheme + "://" + u.netloc if u.scheme else base
        http = HttpClient(session, logger)

        print("[sitemap v2] target: " + base)
        print()

        urls = set()
        sitemaps_found = []  # list of (path, count, is_gz, is_txt)
        visited_sitemaps = set()  # защита от циклов

        # === 1. пробуем 8 типовых путей ===
        for path in PATHS:
            url = origin + path
            if url in visited_sitemaps:
                continue
            visited_sitemaps.add(url)

            try:
                r = http.get(url, allow_redirects=True)
            except Exception:
                continue
            if not r or r.status_code != 200:
                continue

            content = r.content or b""
            if len(content) < 50:
                continue

            text = None
            is_gz = False
            is_txt = path.endswith(".txt")

            # 1. gzip?
            if content[:2] == b"\x1f\x8b":
                text = _try_gzip(content)
                is_gz = True

            # 2. обычный текст
            if text is None:
                text = content.decode("utf-8", errors="ignore")

            # 3. проверка что это реально sitemap (а не SPA-заглушка)
            text_low = text.lower()
            is_real = (
                "<urlset" in text_low or
                "<sitemapindex" in text_low or
                (is_txt and "http" in text_low[:500])
            )
            if not is_real:
                continue

            found = _extract_urls(text, is_gz=is_gz, is_txt=is_txt)
            if not found:
                continue

            sitemaps_found.append({
                "path": path,
                "count": len(found),
                "is_gz": is_gz,
                "is_txt": is_txt,
            })
            marker = " [gz]" if is_gz else (" [txt]" if is_txt else "")
            print("  [+] " + path + " -> " + str(len(found)) + " urls" + marker)

            # nested sitemap_index — XML файлы внутри → рекурсия до 2 уровней
            if "<sitemapindex" in text_low:
                nested = [x for x in found if x.endswith(".xml") or x.endswith(".xml.gz")][:10]
                for sm_url in nested:
                    if sm_url in visited_sitemaps:
                        continue
                    visited_sitemaps.add(sm_url)
                    try:
                        sr = http.get(sm_url, allow_redirects=True)
                    except Exception:
                        continue
                    if not sr or sr.status_code != 200:
                        continue
                    scontent = sr.content or b""
                    stext = None
                    if scontent[:2] == b"\x1f\x8b":
                        stext = _try_gzip(scontent)
                    if stext is None:
                        stext = scontent.decode("utf-8", errors="ignore")
                    nested_urls = _extract_urls(stext)
                    urls.update(nested_urls)
                    print("     nested " + sm_url[:60] + " -> " + str(len(nested_urls)))
            else:
                urls.update(found)

        # === 2. robots.txt → Sitemap: directives ===
        try:
            rb = http.get(origin + "/robots.txt", allow_redirects=True)
        except Exception:
            rb = None

        if rb and rb.status_code == 200:
            rtext = rb.text or ""
            rsm = RE_SITEMAP_DIRECTIVE.findall(rtext)
            if rsm:
                print()
                print("  [robots.txt] " + str(len(rsm)) + " Sitemap: directives")
                for sm_url in rsm[:5]:
                    if sm_url in visited_sitemaps:
                        continue
                    visited_sitemaps.add(sm_url)
                    print("     " + sm_url[:80])
                    try:
                        sr = http.get(sm_url, allow_redirects=True)
                    except Exception:
                        continue
                    if not sr or sr.status_code != 200:
                        continue
                    scontent = sr.content or b""
                    stext = None
                    if scontent[:2] == b"\x1f\x8b":
                        stext = _try_gzip(scontent)
                    if stext is None:
                        stext = scontent.decode("utf-8", errors="ignore")
                    nested_urls = _extract_urls(stext)
                    urls.update(nested_urls)

        # === 3. sensitive path detection ===
        sensitive = sorted([u for u in urls if _is_sensitive(u)])

        # === 4. output ===
        print()
        print("[sitemap v2] total: " + str(len(urls)) + " unique URLs")
        print("[sitemap v2] sitemaps found: " + str(len(sitemaps_found)))

        if sensitive:
            print()
            print("[sitemap v2] sensitive URLs (" + str(len(sensitive)) + "):")
            for s in sensitive[:20]:
                print("  " + s)

        # === 5. findings ===
        findings_count = 0
        try:
            if sitemaps_found:
                logger.finding("sitemap_summary", "info",
                               base + ": " + str(len(urls)) + " urls in " +
                               str(len(sitemaps_found)) + " sitemap(s)")
                findings_count += 1
            for s in sensitive[:10]:
                logger.finding("sitemap_sensitive", "medium", s)
                findings_count += 1
            for sm in sitemaps_found:
                if sm["is_gz"]:
                    logger.finding("sitemap_gz", "info", sm["path"])
                    findings_count += 1
        except Exception:
            pass

        print()
        print("[sitemap v2] findings: " + str(findings_count))

        return {
            "urls": sorted(urls)[:2000],
            "sitemaps": sitemaps_found,
            "sensitive": sensitive,
            "robots_sitemaps": rsm if rb and rb.status_code == 200 else [],
        }
