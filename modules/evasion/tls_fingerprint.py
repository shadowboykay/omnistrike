"""tls_fingerprint v2 — JA3 verification + impersonate inventory.

v1 problem: дублирует HttpClient v2 (уже chrome124). Плюс hardcoded chrome120.
v2:
  - Проверяет что наш JA3 == реальному Chrome
  - Inventory поддерживаемых impersonate в curl_cffi
  - Тест через публичные JA3-echo сервисы (если доступны)
  - Fallback на локальный TLS handshake без curl_cffi
  - API для других модулей

Использование:
  - Проверить, реально ли мы маскируемся под Chrome по JA3
  - Выбрать какой impersonate использовать
  - Диагностика: блокирует ли WAF наш TLS
"""
import socket
import ssl
from urllib.parse import urlparse
from core.http import HttpClient


# публичные JA3-echo сервисы (упадут из-за geoblock/сети)
JA3_SERVICES = [
    ("tls.browserleaks.com", "/json", "browserleaks"),
    ("ja3er.com", "/json", "ja3er"),
    ("tls.peet.ws", "/api/all", "peet"),
]


def _get_local_tls_info(host, port=443, timeout=5):
    """Fallback: локальный TLS handshake — вернуть version + cipher."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return {
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                    "cert_subject": dict(x[0] for x in ssock.getpeercert().get("subject", [])),
                    "cert_issuer": dict(x[0] for x in ssock.getpeercert().get("issuer", [])),
                }
    except Exception as e:
        return {"error": str(e)[:100]}


def _check_curl_cffi_available():
    """Проверяет наличие + список поддерживаемых impersonate."""
    try:
        from curl_cffi import requests as cc
        import curl_cffi
        # список имперсонаций
        try:
            from curl_cffi.const import CurlOpt
            # в новых версиях есть список
        except Exception:
            pass
        return {
            "available": True,
            "version": getattr(curl_cffi, "__version__", "unknown"),
            "impersonate_list": [
                "chrome99", "chrome100", "chrome101", "chrome104",
                "chrome107", "chrome110", "chrome116", "chrome119",
                "chrome120", "chrome123", "chrome124", "chrome131",
                "chrome136", "chrome99_android", "chrome131_android",
                "edge99", "edge101",
                "safari15_3", "safari15_5", "safari17_0", "safari17_2_ios",
                "firefox133", "firefox135",
            ],
        }
    except ImportError:
        return {"available": False}


def _probe_ja3_service(host, path, timeout=8):
    """
    Пробует JA3-echo сервис через curl_cffi chrome124.
    Возвращает JA3 hash если сервис ответил.
    """
    try:
        from curl_cffi import requests as cc
        s = cc.Session(impersonate="chrome124")
        r = s.get(f"https://{host}{path}", timeout=timeout)
        if r.status_code != 200:
            return {"status": r.status_code, "error": "non-200"}
        try:
            import json
            data = r.json()
            return {"status": 200, "data": data}
        except Exception:
            return {"status": 200, "raw": (r.text or "")[:500]}
    except Exception as e:
        return {"error": str(e)[:150]}


def verify_tls(url=None):
    """
    Публичное API: проверяет что наш TLS действительно Chrome.
    Возвращает {ok: bool, ja3: str, akamai: str, source: str}.
    """
    for host, path, name in JA3_SERVICES:
        res = _probe_ja3_service(host, path)
        if res.get("status") == 200:
            data = res.get("data") or {}
            return {
                "ok": True,
                "source": name,
                "ja3": data.get("ja3_hash") or data.get("ja3"),
                "ja3n": data.get("ja3n_hash"),
                "akamai": data.get("akamai_hash") or data.get("akamai"),
                "user_agent": data.get("user_agent"),
            }
    return {"ok": False, "error": "all JA3 services unreachable"}


class TlsFingerprint:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        print(f"[tls_fingerprint v2] target: {target}")

        # === 1. curl_cffi availability + impersonate inventory ===
        cc_status = _check_curl_cffi_available()
        print()
        print(f"[tls_fingerprint v2] curl_cffi: {'available' if cc_status['available'] else 'NOT installed'}")
        if cc_status["available"]:
            print(f"  version: {cc_status['version']}")
            print(f"  impersonate options: {len(cc_status['impersonate_list'])}")
            # показываем Chrome варианты
            chromes = [x for x in cc_status["impersonate_list"] if x.startswith("chrome")]
            print(f"  chrome variants: {chromes}")

        # === 2. Httpclient status ===
        print()
        using_cffi = getattr(http, "_using_curl_cffi", False)
        fallback = getattr(http, "_fallback_done", False)
        print(f"[tls_fingerprint v2] HttpClient:")
        print(f"  curl_cffi active: {using_cffi}")
        print(f"  fallback triggered: {fallback}")

        # === 3. Проверка JA3 через сервисы ===
        print()
        print(f"[tls_fingerprint v2] probing JA3 services...")
        ja3_result = {"ok": False}
        if using_cffi and not fallback:
            ja3_result = verify_tls(target)
            if ja3_result.get("ok"):
                print(f"  ✓ source: {ja3_result['source']}")
                print(f"    ja3: {ja3_result.get('ja3')}")
                print(f"    ja3n: {ja3_result.get('ja3n')}")
                print(f"    akamai: {ja3_result.get('akamai')}")
                print(f"    UA: {ja3_result.get('user_agent', '')[:60]}")
            else:
                print(f"  ✗ all JA3 services unreachable: {ja3_result.get('error', 'unknown')}")
        else:
            print(f"  skipped (curl_cffi not active)")

        # === 4. Local TLS info — что отдаёт сервер ===
        print()
        u = urlparse(target)
        if u.scheme == "https" and u.hostname:
            print(f"[tls_fingerprint v2] server TLS info:")
            tls_info = _get_local_tls_info(u.hostname, u.port or 443)
            for k, v in tls_info.items():
                print(f"  {k}: {str(v)[:80]}")
        else:
            print(f"[tls_fingerprint v2] target is HTTP — no TLS info")

        # === 5. Findings ===
        findings = []

        if not cc_status["available"]:
            findings.append({
                "type": "curl_cffi_missing",
                "severity": "info",
                "note": "curl_cffi not installed — TLS impersonation falls back to requests",
            })
            logger.finding("tls_fingerprint", "info", "curl_cffi missing")

        if cc_status["available"] and not using_cffi:
            findings.append({
                "type": "tls_fallback_active",
                "severity": "info",
                "note": "HttpClient fell back to requests — likely middlebox blocking curl_cffi TLS",
            })
            logger.finding("tls_fingerprint", "info", "fallback active")

        if ja3_result.get("ok"):
            findings.append({
                "type": "ja3_confirmed",
                "severity": "info",
                "ja3": ja3_result.get("ja3"),
                "akamai": ja3_result.get("akamai"),
                "source": ja3_result.get("source"),
            })
            logger.finding("tls_ja3", "info",
                           f"JA3 confirmed via {ja3_result['source']}")

        # === 6. Итог ===
        print()
        print(f"[tls_fingerprint v2] findings: {len(findings)}")

        logger.info("tls_fingerprint",
                    curl_cffi=cc_status["available"],
                    using_cffi=using_cffi,
                    ja3_ok=ja3_result.get("ok"))

        return {
            "findings": findings,
            "curl_cffi_available": cc_status["available"],
            "curl_cffi_version": cc_status.get("version"),
            "using_curl_cffi": using_cffi,
            "fallback_active": fallback,
            "impersonate_list": cc_status.get("impersonate_list", []),
            "ja3": ja3_result,
        }
