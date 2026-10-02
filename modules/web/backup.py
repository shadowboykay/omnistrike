"""backup v2 — baseline-aware: soft-404 detection + size gate"""
import secrets, string
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

# минимальный размер настоящего backup/конфига
MIN_BACKUP_SIZE = 200


def random_path(n=16):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


class Backup:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        found = []

        # === soft-404 detection: 3 рандомных пути ===
        soft_404_signatures = []
        for _ in range(3):
            rnd = random_path(20)
            r = http.get(base + "/" + rnd + ".bak")
            if r and r.status_code == 200:
                soft_404_signatures.append({
                    "len": len(r.content),
                    "ct": r.headers.get("Content-Type", ""),
                    "body_hash": hash(r.text[:500]),
                })

        soft_404_detected = len(soft_404_signatures) >= 2
        if soft_404_detected:
            print(f"[backup v2] soft-404 detected — server returns 200 on random paths")
            print(f"[backup v2] enabling strict mode (skip HTML pages matching soft-404 signature)")

        for p in PATTERNS:
            r = http.get(base + "/" + p)
            if not r:
                continue
            if r.status_code != 200:
                continue

            size = len(r.content)
            ct = r.headers.get("Content-Type", "")

            # 1. пустые ответы — не backup
            if size == 0:
                continue

            # 2. слишком маленькие — заглушка
            if size < MIN_BACKUP_SIZE:
                continue

            # 3. HTML-страница (не файл backup) — если это не .env/.git (там HTML быть не должно)
            #    .env, .git/config, .htaccess — должны быть text/plain или octet-stream
            is_binary_target = any(k in p for k in (".env", ".git", ".htaccess", ".htpasswd", ".svn", ".DS_Store", ".bak", ".old", ".sql", ".zip", ".tar"))
            if is_binary_target and "text/html" in ct:
                # для backup-файлов HTML — явный признак soft-404
                continue

            # 4. в strict-режиме (soft-404) — сравниваем с сигнатурой
            if soft_404_detected:
                body_hash = hash(r.text[:500])
                same_len = any(abs(size - s["len"]) < 100 for s in soft_404_signatures)
                same_hash = any(body_hash == s["body_hash"] for s in soft_404_signatures)
                if same_len or same_hash:
                    continue

            # 5. verify: повтор 2×, размер должен быть стабилен
            import time as _t
            _t.sleep(0.2)
            r2 = http.get(base + "/" + p)
            if not r2 or r2.status_code != 200 or abs(len(r2.content) - size) > 50:
                continue

            found.append({"path": p, "size": size, "ct": ct})
            print(f"  [+] {p} ({size}b, {ct})")
            logger.finding(
                "exposed_file",
                "high" if any(k in p for k in (".env", ".git", "config", "backup")) else "medium",
                p,
            )

        print(f"[backup v2] done: {len(found)} (soft-404={soft_404_detected})")
        return {"found": found, "soft_404": soft_404_detected}
