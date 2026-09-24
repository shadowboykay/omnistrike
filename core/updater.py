# core/updater.py — auto-download fresh payloads from GitHub repos
import urllib.request
import ssl
from pathlib import Path

PAYLOAD_DIR = Path(__file__).parent.parent / "payloads"

SOURCES = {
    "sqli": [
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-SQLi.txt", "sqli_auto.txt"),
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/quick-SQLi.txt", "sqli_auto2.txt"),
    ],
    "xss": [
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt", "xss_auto.txt"),
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-RSNAKE.txt", "xss_auto2.txt"),
    ],
    "lfi": [
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt", "lfi_auto.txt"),
    ],
    "cmd": [
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt", "cmd_auto.txt"),
    ],
    "xxe": [
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XXE-Fuzzing.txt", "xxe_auto.txt"),
    ],
    "ssrf": [
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSRF/SSRF-URL-Fuzzing.txt", "ssrf_auto.txt"),
    ],
}


def fetch(url, timeout=20):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return None


def update_source(kind, url, dest_name, logger=None):
    data = fetch(url)
    if not data:
        print(f"  ✗ {kind}: fetch failed ({url[:60]})")
        return 0
    # parse markdown lists
    lines = []
    for line in data.splitlines():
        s = line.strip()
        if s.startswith(("-", "*")):
            s = s.lstrip("-* ").strip()
        if s and not s.startswith("#") and not s.startswith("```"):
            lines.append(s)
    # dedupe
    lines = list(dict.fromkeys(lines))[:3000]
    if not lines:
        return 0
    dest = PAYLOAD_DIR / dest_name
    dest.write_text("\n".join(lines))
    print(f"  ✓ {kind}: {len(lines)} payloads -> {dest.name}")
    return len(lines)


def update_all(logger=None):
    print("[updater] fetching fresh payloads...")
    total = 0
    for kind, sources in SOURCES.items():
        for url, dest in sources:
            n = update_source(kind, url, dest, logger)
            total += n
    print(f"[updater] total: {total} new payloads")
    return total


if __name__ == "__main__":
    update_all()
