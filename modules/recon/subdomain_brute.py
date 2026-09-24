"""subdomain_brute — DNS subdomain enumeration via wordlist + wildcard filter"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DEFAULT_WORDLIST = [
    "www","mail","ftp","webmail","smtp","pop","ns1","ns2","ns3","dev","test","stage",
    "staging","api","app","admin","portal","blog","shop","store","cdn","static","assets",
    "img","images","media","video","download","uploads","files","docs","doc","wiki","help",
    "support","status","monitor","metrics","grafana","kibana","prometheus","jenkins","ci",
    "git","gitlab","github","bitbucket","jira","confluence","nexus","registry","docker",
    "k8s","kubernetes","vpn","remote","rdp","ssh","db","database","mysql","postgres","redis",
    "mongo","elastic","cache","queue","mq","kafka","rabbit","backup","bak","old","new",
    "v1","v2","v3","beta","alpha","demo","sandbox","preview","qa","uat","prod","prod2",
    "internal","intranet","extranet","corp","office","mail2","webdisk","cpanel","whm",
    "autodiscover","autoconfig","m","mobile","wap","secure","ssl","login","auth","sso",
    "oauth","id","account","accounts","pay","payment","billing","invoice","crm","erp",
    "hr","jobs","careers","recruit","learn","edu","training","events","news","press",
    "forum","community","chat","meet","zoom","teams","calendar","drive","cloud","storage",
]


def resolve(host):
    try:
        return host, socket.gethostbyname(host)
    except Exception:
        return host, None


class SubdomainBrute:
    def run(self, session, logger):
        domain = session.target.replace("https://", "").replace("http://", "").split("/")[0]
        wordlist_path = None
        for x in session.extra:
            if x.startswith("wordlist="):
                wordlist_path = x.split("=", 1)[1]

        if wordlist_path and Path(wordlist_path).is_file():
            words = [l.strip() for l in Path(wordlist_path).read_text().splitlines() if l.strip()]
        else:
            words = DEFAULT_WORDLIST

        logger.info("brute_start", domain=domain, count=len(words))
        print(f"[subdomain] {domain} — {len(words)} words, {session.threads} threads")

        # wildcard check
        wildcard_ip = None
        _, wildcard_ip = resolve(f"this-does-not-exist-{hash(domain) & 0xffff}.{domain}")
        if wildcard_ip:
            logger.warn("wildcard_dns", ip=wildcard_ip)
            print(f"[subdomain] [!] wildcard DNS -> {wildcard_ip}, filtering")

        found = []
        with ThreadPoolExecutor(max_workers=session.threads) as ex:
            futs = {ex.submit(resolve, f"{w}.{domain}"): w for w in words}
            for fut in as_completed(futs):
                host, ip = fut.result()
                if ip and ip != wildcard_ip:
                    found.append((host, ip))
                    print(f"  [+] {host:40s} {ip}")
                    logger.finding("subdomain", "info", f"{host} -> {ip}")

        print(f"[subdomain] done: {len(found)} found")
        return {"domain": domain, "found": [{"host": h, "ip": i} for h, i in found]}
