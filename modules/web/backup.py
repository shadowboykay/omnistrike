"""backup — backup/config file discovery"""
from core.http import HttpClient

PATTERNS = [
    "backup.zip","backup.tar.gz","backup.rar","backup.sql","dump.sql","db.sql",
    "database.sql","export.sql","site.zip","www.zip","web.zip","app.zip",
    ".env",".env.bak",".env.old",".env.example",".env.prod",".env.dev",
    "config.php.bak","wp-config.php.bak","wp-config.php.old","configuration.php.bak",
    "config.yml.bak","config.json.bak","settings.py.bak",
    "index.php.bak","index.php.old","index.php~",".index.php.swp",
    "phpinfo.php","info.php","test.php",".git/config",".git/HEAD",".svn/entries",
    ".DS_Store",".htaccess",".htpasswd","web.config.bak",
]

class Backup:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        found = []
        for p in PATTERNS:
            r = http.get(base + "/" + p)
            if r and r.status_code == 200 and len(r.content) > 0:
                # filter false positives: generic html error pages
                if "text/html" in r.headers.get("Content-Type","") and len(r.content) < 500:
                    continue
                found.append({"path": p, "size": len(r.content), "ct": r.headers.get("Content-Type","")})
                print(f"  [+] {p} ({len(r.content)}b)")
                logger.finding("exposed_file", "high" if any(k in p for k in (".env",".git","config","backup")) else "medium", p)
        print(f"[backup] done: {len(found)}")
        return {"found": found}
