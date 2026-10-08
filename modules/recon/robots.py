"""robots v2 — full robots.txt parser + disallow verification + variants.

Что делает:
  1. Пробует 5 вариантов пути: /robots.txt, /robots.php, /robot.txt,
     /robots.txt.bak, /robots.txt.old
  2. Полный парсер: User-agent, Disallow, Allow, Sitemap, Crawl-delay,
     Host, Clean-param
  3. Комментарии — часто содержат TODO/FIXME/имя автора
  4. Проверка disallowed-путей: GET top-5 → если 200 → misconfig
  5. Sitemap URLs → список для следующего шага
  6. Findings: summary (info) + accessible_disallow (medium) + comment_leak (low)
"""
import re
import secrets
from urllib.parse import urlparse
from core.http import HttpClient


ROBOTS_PATHS = [
    "/robots.txt",
    "/robots.php",
    "/robot.txt",
    "/robots.txt.bak",
    "/robots.txt.old",
]

# парсеры строк
RE_USERAGENT = re.compile(r"^\s*User-agent:\s*(.+)$", re.I | re.M)
RE_DISALLOW = re.compile(r"^\s*Disallow:\s*(.+)$", re.I | re.M)
RE_ALLOW = re.compile(r"^\s*Allow:\s*(.+)$", re.I | re.M)
RE_SITEMAP = re.compile(r"^\s*Sitemap:\s*(\S+)", re.I | re.M)
RE_CRAWLDELAY = re.compile(r"^\s*Crawl-delay:\s*(\S+)", re.I | re.M)
RE_HOST = re.compile(r"^\s*Host:\s*(.+)$", re.I | re.M)
RE_CLEANPARAM = re.compile(r"^\s*Clean-param:\s*(.+)$", re.I | re.M)
RE_COMMENT = re.compile(r"#\s*(.+)$", re.M)

# чувствительные ключи в путях
SENSITIVE_KEYS = [
    "admin", "backup", "config", "private", "api", "db", "secret",
    "dump", "test", "dev", "staging", "internal", ".git", ".env",
    "phpmyadmin", "wp-admin", "shell", "upload", "log", "debug",
]

# интересные ключи в комментариях
INTERESTING_COMMENTS = [
    "todo", "fixme", "hack", "author:", "written by", "password",
    "secret", "key:", "token:", "dont", "don't", "bug",
]


def _clean_path(p):
    """Убирает лишнее из disallow-значения."""
    if not p:
        return ""
    p = p.strip()
    # strip quotes
    if p.startswith('"') and p.endswith('"'):
        p = p[1:-1]
    return p


def _is_sensitive(path):
    low = path.lower()
    return any(k in low for k in SENSITIVE_KEYS)


class Robots:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        u = urlparse(base)
        origin = u.scheme + "://" + u.netloc if u.scheme else base
        http = HttpClient(session, logger)

        print("[robots v2] target: " + base)
        print()

        # === 1. try multiple paths ===
        found = None
        found_path = None
        for path in ROBOTS_PATHS:
            url = origin + path
            try:
                r = http.get(url, allow_redirects=True)
            except Exception:
                continue
            if not r or r.status_code != 200:
                continue
            text = r.text or ""
            # проверка что это реально robots.txt (а не SPA 200-заглушка)
            if "User-agent" in text or "Disallow" in text or "Sitemap" in text:
                found = text
                found_path = path
                print("[robots v2] found: " + url + " (" + str(len(text)) + "b)")
                break
            else:
                print("  skip " + url + " — 200 но не robots.txt")

        if not found:
            print("[robots v2] no robots.txt found at any path")
            return {"disallow": [], "raw": "", "path": None}

        # === 2. parse all directives ===
        ua = [x.strip() for x in RE_USERAGENT.findall(found)]
        disallow = [_clean_path(x) for x in RE_DISALLOW.findall(found) if _clean_path(x)]
        allow = [_clean_path(x) for x in RE_ALLOW.findall(found) if _clean_path(x)]
        sitemaps = [x.strip() for x in RE_SITEMAP.findall(found) if x.strip()]
        crawl_delay = [x.strip() for x in RE_CRAWLDELAY.findall(found)]
        host_directive = [x.strip() for x in RE_HOST.findall(found)]
        clean_param = [x.strip() for x in RE_CLEANPARAM.findall(found)]
        comments = [c.strip() for c in RE_COMMENT.findall(found) if c.strip()]

        print()
        print("[robots v2] directives:")
        print("  User-agent:  " + str(ua[:5]))
        print("  Disallow:    " + str(len(disallow)) + " entries")
        print("  Allow:       " + str(len(allow)))
        print("  Sitemap:     " + str(len(sitemaps)))
        if crawl_delay:
            print("  Crawl-delay: " + str(crawl_delay[:3]))
        if host_directive:
            print("  Host:        " + str(host_directive[:3]))

        # === 3. interesting disallow paths ===
        interesting = [p for p in disallow if _is_sensitive(p)]
        if interesting:
            print()
            print("[robots v2] interesting disallow paths:")
            for p in interesting[:20]:
                print("  " + p)

        # === 4. verify top-5 disallow — accessible? ===
        print()
        print("[robots v2] verifying disallow paths (top 5):")
        accessible = []
        to_test = []
        # только конкретные пути (без * и $)
        for p in disallow[:20]:
            if "*" in p or "$" in p:
                continue
            if not p.startswith("/"):
                continue
            to_test.append(p)
            if len(to_test) >= 5:
                break

        for p in to_test:
            url = origin + p
            try:
                r = http.get(url, allow_redirects=False)
            except Exception:
                continue
            if not r:
                continue
            code = r.status_code
            size = len(r.content)
            marker = " [ACCESSIBLE]" if code == 200 else ""
            print("  " + p + " -> " + str(code) + " (" + str(size) + "b)" + marker)
            if code == 200 and size > 0:
                accessible.append({"path": p, "status": code, "size": size})

        # === 5. interesting comments ===
        leaky = []
        for c in comments:
            low = c.lower()
            for key in INTERESTING_COMMENTS:
                if key in low:
                    leaky.append(c[:120])
                    break

        if leaky:
            print()
            print("[robots v2] interesting comments (" + str(len(leaky)) + "):")
            for c in leaky[:5]:
                print("  " + c)

        # === 6. findings ===
        findings_count = 0
        try:
            logger.finding("robots_summary", "info",
                           found_path + ": " + str(len(disallow)) + " disallow, " +
                           str(len(sitemaps)) + " sitemap")
            findings_count += 1

            for a in accessible:
                logger.finding("robots_accessible_disallow", "medium",
                               a["path"] + " (200, " + str(a["size"]) + "b)")
                findings_count += 1

            for c in leaky[:3]:
                logger.finding("robots_comment_leak", "low", c)
                findings_count += 1

            for s in sitemaps:
                logger.finding("robots_sitemap", "info", s)
                findings_count += 1
        except Exception:
            pass

        print()
        print("[robots v2] findings: " + str(findings_count))

        return {
            "path": found_path,
            "user_agents": ua,
            "disallow": disallow,
            "allow": allow,
            "sitemaps": sitemaps,
            "crawl_delay": crawl_delay,
            "host": host_directive,
            "comments": comments,
            "interesting_paths": interesting,
            "accessible": accessible,
            "leaky_comments": leaky,
            "raw": found,
        }
