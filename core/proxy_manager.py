# core/proxy_manager.py — auto-download + verify + rotate proxies
import re, time, json
from pathlib import Path
import requests


PROXY_DIR = Path(__file__).parent.parent / "proxies"
PROXY_DIR.mkdir(exist_ok=True)
CACHE = PROXY_DIR / "working.json"

# sources for free proxies (public lists)
SOURCES = {
    "https": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    ],
    "socks4": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    ],
    "socks5": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    ],
}


def fetch(url, timeout=15):
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return ""


def download_proxies(kind="https", limit=500):
    out = []
    for url in SOURCES.get(kind, []):
        text = fetch(url)
        for line in text.splitlines():
            line = line.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", line):
                out.append(f"{kind}://{line}")
    out = list(dict.fromkeys(out))
    print(f"  [{kind}] downloaded {len(out)} candidates")
    return out[:limit]


def check_proxy(proxy, test_url="http://httpbin.org/ip", timeout=8):
    try:
        r = requests.get(test_url, proxies={"http": proxy, "https": proxy},
                         timeout=timeout, verify=False)
        if r.status_code == 200:
            return True, r.text[:200]
    except Exception:
        pass
    return False, ""


def verify_batch(proxies, threads=30):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    working = []
    def check(p):
        ok, _ = check_proxy(p, timeout=6)
        return p if ok else None
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(check, p) for p in proxies]
        for i, f in enumerate(as_completed(futs), 1):
            r = f.result()
            if r:
                working.append(r)
                print(f"    ✓ {r} ({len(working)} working)")
    return working


def load_cache():
    if CACHE.is_file():
        try:
            return json.loads(CACHE.read_text())
        except Exception:
            return []
    return []


def save_cache(proxies):
    CACHE.write_text(json.dumps(proxies, indent=2))


def update_all(kinds=("https","socks5","socks4"), limit=200):
    all_candidates = []
    for kind in kinds:
        all_candidates.extend(download_proxies(kind, limit=limit))
    print(f"[proxy] verifying {len(all_candidates)} proxies...")
    working = verify_batch(all_candidates)
    save_cache(working)
    print(f"[proxy] {len(working)} working → {CACHE}")
    return working


def pick_random(proxy_type=None):
    working = load_cache()
    if not working:
        return None
    import random
    if proxy_type:
        working = [p for p in working if p.startswith(proxy_type)]
    return random.choice(working) if working else None


if __name__ == "__main__":
    update_all()
