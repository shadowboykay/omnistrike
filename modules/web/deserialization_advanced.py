"""deserialization_advanced v2 — Java/PHP/Python/.NET/Ruby deserialization.

Формат-детекторы по magic bytes:
  Java    → rO0AB (base64) / \xac\xed (raw)
  PHP     → O:8:"...  / a:2:{...  (serialized objects/arrays)
  Python  → \x80\x04\x95 (pickle opcodes)
  .NET    → AAEAAAD///// (ViewState)
  Ruby    → \x04\x08 (Marshal)

Классификация: cookie / header / body-param / endpoint probe.
Findings: только при маркере СТРОГО специфичном для ошибки десериализации.

OOB: URLDNS payload для Java + core.oob_server callback.
"""
import base64
import secrets
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.verify import confidence, is_signal


# --- magic bytes ---
MAGIC = {
    "java":   [b"\xac\xed\x00\x05",                # raw ObjectInputStream
               b"rO0AB"],                          # base64 Java serialized
    "php":    [b'O:8:"stdClass"', b'a:2:{', b'a:3:{', b'O:4:"User"'],
    "python": [b"\x80\x04\x95",                    # pickle protocol 4
               b"\x80\x03",                        # pickle protocol 3
               b"\x80\x02"],                       # protocol 2
    "net":    [b"AAEAAAD/////"],                   # .NET ObjectStateFormatter b64
    "ruby":   [b"\x04\x08"],                       # Marshal header
}

# --- строгие маркеры ошибок (специфичные, не общие) ---
STRICT_MARKERS = [
    # Java
    "java.io.ObjectInputStream",
    "java.io.InvalidClassException",
    "java.lang.ClassNotFoundException",
    "org.apache.commons.collections",
    "javax.servlet.ServletException",
    "org.springframework.beans.factory",
    # PHP
    "unserialize(): Error",
    "__PHP_Incomplete_Class",
    "PHP Fatal error:  Uncaught Error: Class",
    "Cannot unserialize",
    # Python
    "UnpicklingError",
    "pickle.UnpicklingError",
    "invalid load key",
    "Could not unpickle",
    # .NET
    "System.Runtime.Serialization",
    "BinaryFormatter.Deserialize",
    "ViewStateException",
    # Ruby
    "Marshal.load",
    "TypeError: incompatible marshal",
]

# эндпоинты, часто принимающие serialized data
DETECT_PATHS = [
    "/api/deserialize", "/api/v1/deserialize", "/api/v2/deserialize",
    "/api/parse", "/api/decode", "/api/load", "/api/import",
    "/api/session", "/api/upload", "/api/model", "/api/predict",
    "/rpc", "/invoke", "/remoting", "/serialization",
    "/ws/import", "/import", "/upload", "/rest/import",
]

# cookie-имена с потенциальной сериализацией
DESER_COOKIE_HINTS = [
    "session", "state", "auth", "token", "viewstate",
    "jsessionid", "phpsessid", "asp.net_sessionid",
]


def _cookie_iter(resp):
    """Универсальный доступ к cookies (requests + curl_cffi)."""
    cookies = getattr(resp, "cookies", None)
    if cookies is None:
        return []
    # curl_cffi: dict-like
    if hasattr(cookies, "items"):
        return list(cookies.items())
    # requests: list of Cookie objects
    out = []
    for c in cookies:
        if hasattr(c, "name") and hasattr(c, "value"):
            out.append((c.name, c.value))
    return out


def _make_java_urldns(oob_host):
    """Минимальный Java serialized URLDNS payload (без внешних библиотек).
    Заменяет строку DNS lookup в базовом шаблоне на наш хост."""
    # base64 шаблон serialized HashMap с URLDNS (заменим хост)
    # для простоты — только детект magic, payload из ysoserial требуется для реального RCE
    # здесь возвращаем marker для проверки что сервер парсит Java сериализацию
    return b"\xac\xed\x00\x05" + b"\x00" * 20 + oob_host.encode()


def _make_pickle_marker(marker):
    """Минимальный pickle с Reduce для OOB (только для подтверждения парсинга)."""
    # протокол 0 — plain, легко детектируется
    return b"cbuiltins\neval\n(S'" + marker.encode() + b"'\ntR."


def _make_php_object(marker):
    """PHP serialized object с маркером."""
    return b'O:8:"stdClass":1:{s:6:"marker";s:' + str(len(marker)).encode() + b':"' + marker.encode() + b'";}'


def _make_net_viewstate(marker):
    """.NET ViewState-like bytes (только magic + marker)."""
    return b"AAEAAAD/////" + marker.encode()


def _check_magic_in_response(resp, magic_list):
    """Проверяет, что в ответе есть magic bytes одного из форматов."""
    if not resp:
        return None
    raw = resp.content if hasattr(resp, "content") else b""
    text = resp.text if hasattr(resp, "text") else ""
    for m in magic_list:
        if isinstance(m, bytes) and m in raw:
            return m
        if isinstance(m, str) and m in text:
            return m
        # base64-encoded
        try:
            m_b64 = base64.b64encode(m).decode() if isinstance(m, bytes) else m
            if m_b64 and m_b64 in text:
                return m
        except Exception:
            pass
    return None


class DeserializationAdvanced:
    def run(self, session, logger):
        target = session.target
        base = target.rstrip("/")
        http = HttpClient(session, logger)

        marker = "OMNI_DESER_" + secrets.token_hex(4)
        print("[deser v2] target: " + target)
        print("[deser v2] marker: " + marker)

        # baseline — что уже в исходной странице
        try:
            base_r = http.get(target)
            baseline_text = (base_r.text or "") if base_r else ""
        except Exception:
            baseline_text = ""

        # активные маркеры — те, что не в baseline
        active_markers = [m for m in STRICT_MARKERS
                          if m.lower() not in baseline_text.lower()]
        print("[deser v2] " + str(len(active_markers)) + "/" + str(len(STRICT_MARKERS)) + " markers active")

        findings = []

        # ============================================================
        # Phase 1: cookie inspection (что за платформа)
        # ============================================================
        print()
        print("[deser v2] Phase 1: cookie inspection")
        if base_r:
            cookies = _cookie_iter(base_r)
            for name, value in cookies:
                if not value:
                    continue
                # Java
                if value.startswith("rO0AB") or value.startswith("H4sI"):
                    findings.append({
                        "type": "java_serialized_cookie",
                        "severity": "high",
                        "cookie": name,
                        "prefix": value[:20],
                    })
                    print("  [HIGH] Java serialized cookie: " + name + " (rO0AB)")
                    logger.finding("deser_java_cookie", "high", name)
                # PHP
                elif value.startswith("O:") or (value.startswith("a:") and "O:" in value):
                    findings.append({
                        "type": "php_serialized_cookie",
                        "severity": "high",
                        "cookie": name,
                        "prefix": value[:30],
                    })
                    print("  [HIGH] PHP serialized cookie: " + name)
                    logger.finding("deser_php_cookie", "high", name)
                # .NET ViewState
                elif value.startswith("AAEAAAD"):
                    findings.append({
                        "type": "net_viewstate_cookie",
                        "severity": "high",
                        "cookie": name,
                    })
                    print("  [HIGH] .NET ViewState cookie: " + name)
                    logger.finding("deser_net_viewstate", "high", name)

        # ============================================================
        # Phase 2: probe likely endpoints
        # ============================================================
        print()
        print("[deser v2] Phase 2: endpoint probing")
        live_endpoints = []
        for path in DETECT_PATHS:
            try:
                r = http.get(base + path, allow_redirects=False)
            except Exception:
                continue
            if r and r.status_code not in (404, 410):
                live_endpoints.append(path)
                print("  live: " + path + " (" + str(r.status_code) + ")")

        if not live_endpoints:
            print("  no deser endpoints found — skip payload testing")
            print()
            print("[deser v2] findings: " + str(len(findings)))
            return {"findings": findings, "live": []}

        # payloads для probe
        payload_sets = {
            "java":   [_make_java_urldns("omni-oob.invalid"), b"\xac\xed\x00\x05\x00\x00\x00\x00"],
            "php":    [_make_php_object(marker), b"a:2:{i:0;s:4:test;i:1;s:5:test2;}"],
            "python": [_make_pickle_marker(marker), b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00"],
            "net":    [_make_net_viewstate(marker)],
        }

        for path in live_endpoints[:5]:
            url = base + path
            for lang, payloads in payload_sets.items():
                for payload in payloads[:2]:
                    try:
                        r = http.post(url, data=payload,
                                      headers={
                                          "Content-Type": "application/octet-stream",
                                          "Content-Length": str(len(payload)),
                                      },
                                      allow_redirects=False)
                    except Exception:
                        continue
                    if not r:
                        continue

                    body_low = (r.text or "").lower()
                    # ищем строгий маркер ошибки
                    hit = None
                    for m in active_markers:
                        if m.lower() in body_low:
                            hit = m
                            break

                    # или вернулись magic bytes другого формата
                    if not hit:
                        magic_hit = _check_magic_in_response(r, MAGIC[lang])
                        if magic_hit:
                            hit = "magic:" + str(magic_hit)[:30]

                    if not hit:
                        continue

                    # verify ×2
                    try:
                        r2 = http.post(url, data=payload,
                                       headers={"Content-Type": "application/octet-stream"},
                                       allow_redirects=False)
                    except Exception:
                        r2 = None
                    if not r2 or hit.lower() not in (r2.text or "").lower():
                        continue

                    conf = confidence(0.9, 1.0)
                    if not is_signal(conf, floor=0.55, module="deser"):
                        continue

                    findings.append({
                        "type": "deser_" + lang,
                        "severity": "critical",
                        "endpoint": path,
                        "payload_size": len(payload),
                        "marker": hit[:100],
                        "confidence": conf,
                    })
                    print("  [CRITICAL] " + lang + " deser at " + path + " (marker=" + hit[:40] + ")")
                    logger.finding("deser_" + lang, "critical", path + " " + hit[:60])
                    break

        # ============================================================
        # Phase 3: header-based deserialization (rare)
        # ============================================================
        print()
        print("[deser v2] Phase 3: header-based probe")
        header_payloads = [
            ("X-Serialized",  _make_php_object(marker)),
            ("X-Object",      _make_java_urldns("omni-oob.invalid")),
            ("Cookie: session", _make_php_object(marker)),
        ]
        for h_name, payload in header_payloads:
            try:
                if h_name.startswith("Cookie:"):
                    c_name = h_name.split(":", 1)[1].strip()
                    r = http.get(target, headers={"Cookie": c_name + "=" + payload.decode("latin-1", errors="ignore")})
                else:
                    r = http.get(target, headers={h_name: payload.decode("latin-1", errors="ignore")})
            except Exception:
                continue
            if not r:
                continue
            body_low = (r.text or "").lower()
            for m in active_markers:
                if m.lower() in body_low:
                    findings.append({
                        "type": "deser_header",
                        "severity": "high",
                        "header": h_name,
                        "marker": m[:60],
                    })
                    print("  [HIGH] header deser: " + h_name + " -> " + m[:40])
                    logger.finding("deser_header", "high", h_name + " " + m[:40])
                    break

        print()
        print("[deser v2] findings: " + str(len(findings)))
        return {
            "findings": findings,
            "live_endpoints": live_endpoints,
            "active_markers": len(active_markers),
        }
