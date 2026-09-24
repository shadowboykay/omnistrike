"""defense_analyzer — что увидит защитник, когда ты атакуешь"""
from core.http import HttpClient
from core.session import Session
from pathlib import Path
import json
import time


class DefenseAnalyzer:
    """
    Отвечает на вопрос: "Что увидит синяя команда при моей атаке?"
    Проходит по всем типовым детекторам и показывает, что логируется.
    """

    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        print(f"[defense_analyzer] target: {target}")
        print(f"[defense_analyzer] analyzing what SOC/EDR/SIEM will see")
        print()

        # 1. baseline
        print("=" * 60)
        print("1. BASELINE — как я выгляжу сейчас")
        print("=" * 60)
        r = http.get(target)
        if not r:
            print("  ✗ target unreachable")
            return {}
        print(f"  User-Agent: {r.request.headers.get('User-Agent', '?')}")
        print(f"  X-Forwarded-For: {r.request.headers.get('X-Forwarded-For', 'not set')}")
        print(f"  Accept: {r.request.headers.get('Accept', '?')[:60]}")
        print(f"  Accept-Encoding: {r.request.headers.get('Accept-Encoding', '?')}")
        print()

        # 2. typичные детекты
        print("=" * 60)
        print("2. ЧТО ЗАПИШЕТСЯ В ЛОГАХ СЕРВЕРА")
        print("=" * 60)

        # User-Agent check
        ua = r.request.headers.get('User-Agent', '')
        ua_flags = []
        if "python" in ua.lower() or "requests" in ua.lower():
            ua_flags.append("python/requests = палево")
        if "curl" in ua.lower():
            ua_flags.append("curl = автоматизация")
        if "nmap" in ua.lower() or "nikto" in ua.lower():
            ua_flags.append("известный сканер")
        if not ua_flags:
            print("  UA: выглядит как браузер (ok)")

        for flag in ua_flags:
            print(f"  ⚠ UA: {flag}")

        # 3. детект по заголовкам
        print()
        print("=" * 60)
        print("3. ЧТО УВИДИТ EDR/IDS")
        print("=" * 60)

        suspicious_headers = []
        for h in r.request.headers:
            if h.lower().startswith("x-") and "forward" not in h.lower():
                suspicious_headers.append(h)
            if h.lower() in ("x-attack", "x-hacker", "x-exploit"):
                suspicious_headers.append(f"{h} = явное палево")

        if suspicious_headers:
            print(f"  ⚠ кастомные X-headers: {suspicious_headers}")
        else:
            print("  кастомных X-headers нет (ok)")

        # 4. TTL/timing check
        print()
        print("=" * 60)
        print("4. ПОВЕДЕНЧЕСКИЙ АНАЛИЗ (SIEM/UEBA)")
        print("=" * 60)
        times = []
        for i in range(5):
            t0 = time.time()
            http.get(target)
            times.append(time.time() - t0)
            time.sleep(0.5)

        avg = sum(times) / len(times)
        variance = max(times) - min(times)
        print(f"  avg response time: {avg*1000:.0f}ms")
        print(f"  variance: {variance*1000:.0f}ms")

        # repeated requests pattern
        print(f"  5 requests in {sum(times) + 5*0.5:.1f}s")
        if avg < 0.1:
            print(f"  ⚠ быстрые запросы — детект 'high request rate'")
        if variance < 0.05:
            print(f"  ⚠ постоянное время — детект 'bot-like behavior'")
        else:
            print(f"  variance в норме (ok)")

        # 5. DNS check
        print()
        print("=" * 60)
        print("5. DNS / NETWORK ВИДИМОСТЬ")
        print("=" * 60)
        from urllib.parse import urlparse
        u = urlparse(target)
        print(f"  DNS query: {u.hostname}")
        print(f"  → логируется в DNS-сервере компании")
        print(f"  → провайдер видит SNI при HTTPS handshake")
        print(f"  → если TLS 1.3 + ECH — только домен, не путь")

        # 6. итог
        print()
        print("=" * 60)
        print("6. РЕКОМЕНДАЦИИ — как уменьшить видимость")
        print("=" * 60)
        recs = []
        if ua_flags:
            recs.append("Смени User-Agent на браузер (ua_rotate, header_full_spoof)")
        if suspicious_headers:
            recs.append("Убери кастомные X-headers — они уникальны")
        if avg < 0.1:
            recs.append("Замедлись (adaptive_throttle, delay_jitter)")
        if variance < 0.05:
            recs.append("Добавь рандомные паузы (browser_behavior)")
        recs.append("Используй decoy_traffic для маскировки в логах")
        recs.append("Хамелеон-режим подстроит стратегию под цель")

        for i, rec in enumerate(recs, 1):
            print(f"  {i}. {rec}")

        # save
        out = {
            "target": target,
            "ua": ua,
            "ua_flags": ua_flags,
            "suspicious_headers": suspicious_headers,
            "avg_response_ms": round(avg * 1000),
            "variance_ms": round(variance * 1000),
            "recommendations": recs,
        }
        Path("reports").mkdir(exist_ok=True)
        Path("reports/defense_analysis.json").write_text(json.dumps(out, indent=2))
        print(f"\n[defense_analyzer] saved -> reports/defense_analysis.json")

        logger.finding("defense_analysis", "info",
                       f"visible: {len(ua_flags) + len(suspicious_headers)} flags")
        return out
