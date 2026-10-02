"""hpp v2 — HTTP Parameter Pollution: duplicate, array, encoded, mixed-case.

Сигналы:
  1. server_uses_last:  сервер берёт последнее значение (после dup) → override
  2. server_uses_first: сервер берёт первое (безопасно, но полезно для обхода WAF)
  3. server_rejects:    400/422 → можно использовать для DoS / обхода фильтра
  4. type_confusion:    массив принимается как строка / строка как массив

Отличие от v1: не считает рефлексию как finding, сравнивает ответы с baseline.
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.verify import verify, confidence, is_signal
from core.waf_bypass import is_blocked


class Hpp:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query)

        if not params:
            print("[hpp v2] no params in URL")
            return {"findings": []}

        # baseline — единственный параметр с уникальным маркером
        print(f"[hpp v2] target: {target}")
        print(f"[hpp v2] params: {list(params.keys())}")

        findings = []

        for name, vals in params.items():
            original = vals[0]

            # === baseline: с одним параметром ===
            baseline_q = dict(params)
            baseline_q[name] = [original]
            baseline_url = urlunparse(u._replace(query=urlencode(baseline_q, doseq=True)))
            try:
                base_r = http.get(baseline_url)
            except Exception:
                continue
            if not base_r:
                continue
            base_status = base_r.status_code
            base_len = len(base_r.content)
            base_body = base_r.text

            # === HPP-формы: сырые query-строки ===
            marker = "omni_hpp_" + __import__("secrets").token_hex(4)

            forms = [
                ("dup_last",  f"{name}={original}&{name}={marker}"),
                ("dup_first", f"{name}={marker}&{name}={original}"),
                ("array_brackets", f"{name}[]={marker}"),
                ("array_num", f"{name}[0]={marker}"),
                ("comma",     f"{name}={original},{marker}"),
                ("semicolon", f"{name}={original};{name}={marker}"),
                ("case",      f"{name}={original}&{name.capitalize()}={marker}"),
                ("encoded_dup", f"{name}={original}&%7B{name}%7D={marker}"),
                ("null_byte", f"{name}={original}%00&{name}={marker}"),
                ("space_sep", f"{name}={original}%20{name}={marker}"),
                ("plus",      f"{name}={original}+{name}={marker}"),
                ("trailing",  f"{name}={marker}&"),
            ]

            # оставляем другие параметры как есть
            other_q = "&".join(f"{k}={v[0]}" for k, v in params.items() if k != name)
            prefix = (other_q + "&") if other_q else ""

            for label, raw in forms:
                raw_url = urlunparse(u._replace(query=prefix + raw))
                try:
                    r = http.get(raw_url)
                except Exception:
                    continue
                if not r or is_blocked(r):
                    continue

                # === классификация сигнала ===
                signal = None
                strength = 0.5

                # сервер использовал наш маркер (не оригинал) → override
                if marker in r.text and original not in r.text:
                    signal = "server_uses_injected"
                    strength = 0.75
                # сервер использовал оба
                elif marker in r.text and original in r.text:
                    signal = "server_uses_both"
                    strength = 0.55
                # сервер отклонил с 4xx (валидация дубликата) — тоже сигнал
                elif r.status_code in (400, 422) and base_status not in (400, 422):
                    signal = "server_rejects_dup"
                    strength = 0.5
                # сильный сдвиг длины — тип-конфузия
                elif base_len and abs(len(r.content) - base_len) > 500:
                    signal = "length_shift"
                    strength = 0.45

                if not signal:
                    continue

                # === verify ×2 ===
                def rep():
                    try:
                        return http.get(raw_url)
                    except Exception:
                        return None

                def predicate(s):
                    body = s.get("body", "")
                    status = s.get("status", 0)
                    if marker in body and original not in body:
                        return True
                    if marker in body and original in body:
                        return True
                    if status in (400, 422) and base_status not in (400, 422):
                        return True
                    return False

                ratio, hits = verify(rep, predicate, n=2, delay=0.15)

                conf = confidence(strength, ratio)
                if not is_signal(conf, floor=0.55, module="hpp"):
                    continue

                findings.append({
                    "param": name,
                    "form": label,
                    "signal": signal,
                    "baseline_status": base_status,
                    "response_status": r.status_code,
                    "verify_hits": hits,
                    "confidence": conf,
                })
                print(f"  ✓ HPP {signal}: {name} form={label}")
                logger.finding("hpp", "low",
                               f"{name} {signal} ({label}) conf={int(conf*100)}")
                break  # одного сигнала на param достаточно

        print(f"[hpp v2] findings: {len(findings)}")
        return {"findings": findings}
