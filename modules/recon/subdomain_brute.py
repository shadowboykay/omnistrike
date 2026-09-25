"""subdomain_brute — DNS enumeration via DoH (bypass local wildcard)"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import urllib3
urllib3.disable_warnings()

DOH_URL = "https://dns.google/resolve"

FALLBACK = [
    "www","mail","ftp","smtp","ns1","ns2","api","app","admin","dev","test",
    "stage","staging","blog","shop","cdn","static","assets","images","media",
    "git","gitlab","jenkins","jira","confluence","vpn","remote","db","mysql",
]


def resolve_doh(host, timeout=8):
    """DNS-over-HTTPS via dns.google — bypasses local wildcard resolver."""
    import requests
    try:
        r = requests.get(DOH_URL, params={"name": host, "type": "A"},
                         timeout=timeout, verify=False)
        if r.status_code == 200:
            for a in r.json().get("Answer", []):
                if a.get("type") == 1:
                    return host, a.get("data")
    except Exception:
        pass
    return host, None


def resolve_local(host):
    try:
        return host, socket.gethostbyname(host)
    except Exception:
        return host, None


def is_fake_ip(ip):
    if not ip:
        return True
    # RFC 2544 benchmark
    if ip.startswith("198.18.") or ip.startswith("198.19."):
        return True
    # loopback / unspecified
    if ip.startswith("127.") or ip == "0.0.0.0":
        return True
    # RFC 5737 TEST-NET documentation range
    if ip.startswith("192.0.2.") or ip.startswith("198.51.100.") or ip.startswith("203.0.113."):
        return True
    # RFC 5737 TEST-NET documentation range
    if ip.startswith("192.0.2.") or ip.startswith("198.51.100.") or ip.startswith("203.0.113."):
        return True
    return False


class SubdomainBrute:
    def run(self, session, logger):
        domain = session.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        # wordlist
        words = []
        try:
            from core.wordlist_mgr import load
            words = load("subdomains")
            print(f"[subdomain] loaded {len(words)} from wordlist_mgr")
        except Exception:
            pass

        for x in session.extra:
            if x.startswith("wordlist="):
                p = Path(x.split("=", 1)[1])
                if p.is_file():
                    words = [l.strip() for l in p.read_text().splitlines() if l.strip()]
                    print(f"[subdomain] custom: {len(words)}")

        if not words:
            words = FALLBACK
            print(f"[subdomain] fallback: {len(words)}")

        limit = 20000
        for x in session.extra:
            if x.startswith("limit="):
                limit = int(x.split("=", 1)[1])
        words = words[:limit]

        # use DoH (bypass local wildcard)
        use_doh = True
        for x in session.extra:
            if x == "doh=0":
                use_doh = False

        resolver = resolve_doh if use_doh else resolve_local
        print(f"[subdomain] {domain}, {len(words)} words, {session.threads} threads, "
              f"resolver={'DoH' if use_doh else 'local'}")

        # wildcard check via same resolver
        fake_ips = set()
        for i in range(3):
            rand = f"this-does-not-exist-{abs(hash(domain)) & 0xffff}-{i}.{domain}"
            _, ip = resolver(rand)
            if ip:
                fake_ips.add(ip)

        if fake_ips:
            print(f"[subdomain] wildcard -> {list(fake_ips)}")

        found = []
        with ThreadPoolExecutor(max_workers=session.threads) as ex:
            futs = {ex.submit(resolver, f"{w}.{domain}"): w for w in words}
            for i, fut in enumerate(as_completed(futs), 1):
                host, ip = fut.result()
                if not ip:
                    continue
                if is_fake_ip(ip):
                    continue
                if ip in fake_ips:
                    continue
                found.append((host, ip))
                print(f"  + {host:40s} {ip}")
                logger.finding("subdomain", "info", f"{host} -> {ip}")

        print(f"[subdomain] done: {len(found)}/{len(words)} found")
        return {"domain": domain, "found": [{"host": h, "ip": i} for h, i in found],
                "resolver": "DoH" if use_doh else "local"}
