# core/wordlist_mgr.py — centralized wordlist manager
from pathlib import Path
import json
import requests

DATA_DIR = Path(__file__).parent.parent / "wordlists"
DATA_DIR.mkdir(exist_ok=True)

# Standard wordlists from SecLists (raw, MIT)
WORDLISTS = {
    "dirs_small": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    ],
    "dirs_medium": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
    ],
    "dirs_large": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-big.txt",
    ],
    "subdomains": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
    ],
    "usernames": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt",
    ],
    "passwords": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    ],
    "params": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
    ],
    "api": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
    ],
}


def fetch(url, timeout=60):
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


def download(name, urls=None):
    urls = urls or WORDLISTS.get(name, [])
    if not urls:
        print(f"  ✗ {name}: no URLs configured")
        return 0
    combined = []
    for url in urls:
        print(f"  ↓ {url.split('/')[-1]}")
        text = fetch(url)
        if text:
            combined.extend(text.splitlines())
    combined = list(dict.fromkeys(l.strip() for l in combined if l.strip()))
    out = DATA_DIR / f"{name}.txt"
    out.write_text("\n".join(combined))
    print(f"  ✓ {name}: {len(combined)} entries -> {out.name}")
    return len(combined)


def download_all():
    total = {}
    for name in WORDLISTS:
        total[name] = download(name)
    return total


def load(name):
    p = DATA_DIR / f"{name}.txt"
    if not p.is_file():
        return []
    return [l.strip() for l in p.read_text().splitlines() if l.strip()]


def list_available():
    out = {}
    for name in WORDLISTS:
        p = DATA_DIR / f"{name}.txt"
        if p.is_file():
            out[name] = len(load(name))
        else:
            out[name] = 0
    return out


if __name__ == "__main__":
    download_all()
    print()
    print("Available:")
    for name, n in list_available().items():
        print(f"  {name:14s} {n:6d}")
