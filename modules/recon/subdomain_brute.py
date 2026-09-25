"""subdomain_brute — DNS enumeration with wordlist_mgr integration (20000+ words)"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# fallback small list if wordlists not downloaded
FALLBACK = [
    "www","mail","ftp","smtp","ns1","ns2","api","app","admin","dev","test",
    "stage","staging","blog","shop","cdn","static","assets","images","media",
    "git","gitlab","jenkins","jira","confluence","vpn","remote","db","mysql",
]


def resolve(host):
    try:
        return host, socket.gethostbyname(host)
    except Exception:
        return host, None


class SubdomainBrute:
    def run(self, session, logger):
        domain = session.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        # 1. try wordlist_mgr
        words = []
        try:
            from core.wordlist_mgr import load
            words = load("subdomains")
            print(f"[subdomain] loaded {len(words)} from wordlist_mgr")
        except Exception:
            pass

        # 2. custom via --extra wordlist=
        for x in session.extra:
            if x.startswith("wordlist="):
                p = Path(x.split("=", 1)[1])
                if p.is_file():
                    words = [l.strip() for l in p.read_text().splitlines() if l.strip()]
                    print(f"[subdomain] custom wordlist: {len(words)}")

        # 3. fallback
        if not words:
            words = FALLBACK
            print(f"[subdomain] using fallback: {len(words)} words")

        # limit if too many
        limit = 20000
        for x in session.extra:
            if x.startswith("limit="):
                limit = int(x.split("=", 1)[1])
        words = words[:limit]

        print(f"[subdomain] {domain}, {len(words)} words, {session.threads} threads")
        print(f"[subdomain] wildcard check...")

        # wildcard
        _, wildcard_ip = resolve(f"this-does-not-exist-{abs(hash(domain)) & 0xffff}.{domain}")
        if wildcard_ip:
            print(f"[subdomain] ⚠ wildcard DNS -> {wildcard_ip}")
            logger.warn("wildcard_dns", ip=wildcard_ip)

        found = []
        with ThreadPoolExecutor(max_workers=session.threads) as ex:
            futs = {ex.submit(resolve, f"{w}.{domain}"): w for w in words}
            for i, fut in enumerate(as_completed(futs), 1):
                host, ip = fut.result()
                if ip and ip != wildcard_ip:
                    found.append((host, ip))
                    print(f"  + {host:40s} {ip}")
                    logger.finding("subdomain", "info", f"{host} -> {ip}")
                if i % 500 == 0:
                    print(f"    ... {i}/{len(words)} ({len(found)} found)")

        print(f"[subdomain] done: {len(found)}/{len(words)} found")
        return {"domain": domain, "found": [{"host": h, "ip": i} for h, i in found],
                "total_words": len(words)}
