"""ssti v2 — Server-Side Template Injection with mathematical verification.

Payloads с известным математическим результатом:
  {{7*7}}       -> 49       (Jinja2, Twig, Nunjucks)
  ${7*7}        -> 49       (Freemarker, JSP EL)
  #{7*7}        -> 49       (Ruby, Thymeleaf)
  <%= 7*7 %>    -> 49       (ERB, EJS)
  {{7*'7'}}     -> 7777777  (Jinja2 string multiply)
  ${{7*7}}      -> 49       (Jakarta EL wrapper)
  {{7*7}}       -> 49       (Handlebars — не сработает, но проверим)
  [[${7*7}]]    -> 49       (Thymeleaf)
  {7*7}         -> 49       (Smarty)
  {php}echo 7*7;{/php}      -> 49 (Smarty PHP)
  {{= 7*7 }}    -> 49       (doT.js)
  @(7*7)        -> 49       (Razor)

Уникальные результаты (49, 7777777) — почти никогда в baseline.
"""
import re
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.verify import verify, confidence, is_signal


# (payload, expected_result, engine_hint)
SSTI_PROBES = [
    # --- базовые арифметические с 49 ---
    ("{{7*7}}",         "49",        "jinja2/twig/nunjucks"),
    ("${7*7}",          "49",        "freemarker/jsp-el"),
    ("#{7*7}",          "49",        "ruby/thymeleaf"),
    ("<%= 7*7 %>",      "49",        "erb/ejs"),
    ("${{7*7}}",        "49",        "jakarta-el-wrapper"),
    ("[[${7*7}]]",      "49",        "thymeleaf"),
    ("{7*7}",           "49",        "smarty"),
    ("@(7*7)",          "49",        "razor"),
    ("{{= 7*7 }}",      "49",        "dot.js"),
    # --- уникальные результаты — distinguish Jinja2 от Twig ---
    ("{{7*'7'}}",       "7777777",   "jinja2-string-mult"),  # Jinja2 → 7777777, Twig → 49
    ("{{'7'*7}}",       "7777777",   "jinja2-string-mult-2"),
    # --- арифметика с большим числом для уверенности ---
    ("{{13*13}}",       "169",       "jinja2/twig-distinct"),
    ("${13*13}",        "169",       "freemarker-distinct"),
    ("{{7*7*7}}",       "343",       "multi-mul"),
    # --- конкатенация строк ---
    ("{{'omni'}}",      "omni",      "literal-string"),
    # --- объектные probes (для info-only) ---
    ("{{config}}",      None,        "jinja2-config-dump"),
    ("{{self}}",        "TemplateReference", "jinja2-self"),
    ("${7*7}${7*7}",    "4949",      "double-expr"),
]


def _check_payload(body, payload, expected):
    """
    Проверяет, что expected результат появился в body ПОСЛЕ payload'а.
    Строгая проверка: не должно быть '{{' или '${' вокруг expected.
    """
    if not body or not expected:
        return False

    # payload должен исчезнуть (обработан сервером)
    # expected должен появиться
    idx = body.find(expected)

    if idx == -1:
        return False

    # отсеиваем случай, когда expected уже был в контексте payload'а
    # (т.е. сервер просто вернул payload обратно без обработки)
    # Проверяем: если payload '{{7*7}}' вернулся как '{{7*7}}', а '49' — в другом месте,
    # то это не SSTI
    context = body[max(0, idx - 30): idx + len(expected) + 30]
    # payload не должен быть прямо рядом
    if payload in context:
        return False

    return True


class Ssti:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {"name": ["test"]}

        print(f"[ssti v2] target: {target}")
        print(f"[ssti v2] params: {list(params.keys())}")

        # baseline: что в ответе до инъекции
        try:
            base_r = http.get(target)
            baseline_text = (base_r.text or "") if base_r else ""
        except Exception:
            baseline_text = ""

        # отсеиваем payload'ы, чей expected уже в baseline
        active_probes = []
        for payload, expected, engine in SSTI_PROBES:
            if expected is None:
                active_probes.append((payload, expected, engine))
                continue
            # expected не должен быть в baseline
            if expected not in baseline_text:
                active_probes.append((payload, expected, engine))

        print(f"[ssti v2] {len(active_probes)}/{len(SSTI_PROBES)} probes active (expected not in baseline)")

        findings = []

        for name in params:
            print()
            print(f"[ssti v2] param: {name}")

            for payload, expected, engine in active_probes:
                # строим URL
                q = {k: v[0] for k, v in params.items()}
                q[name] = payload
                test_url = urlunparse(u._replace(query=urlencode(q, doseq=True)))

                try:
                    r = http.get(test_url)
                except Exception:
                    continue
                if not r:
                    continue

                body = r.text or ""

                # для payload'ов без expected — проверяем только признаки
                if expected is None:
                    # {{config}} → SECRET, {{self}} → TemplateReference
                    if payload == "{{config}}" and "SECRET" in body and "SECRET" not in baseline_text:
                        conf = confidence(0.7, 1.0)
                        if is_signal(conf, floor=0.55, module="ssti"):
                            findings.append({
                                "type": "ssti_config_leak",
                                "severity": "high",
                                "param": name,
                                "payload": payload,
                                "confidence": conf,
                            })
                            print(f"  config leak")
                            logger.finding("ssti", "high", f"{name} config leak")
                            break
                    continue

                # строгая проверка результата
                if not _check_payload(body, payload, expected):
                    continue

                # verify ×2
                def rep():
                    try:
                        return http.get(test_url)
                    except Exception:
                        return None

                def predicate(s):
                    return _check_payload(s.get("body", ""), payload, expected)

                ratio, hits = verify(rep, predicate, n=2, delay=0.2)

                # confidence: если expected короткий (49) — риск ложняка от других '49' в HTML
                # если expected уникальный (7777777, 169, 343) — выше
                if expected in ("49",):
                    strength = 0.75
                elif expected in ("7777777", "343", "169"):
                    strength = 0.95
                elif expected == "4949":
                    strength = 0.9
                else:
                    strength = 0.85

                conf = confidence(strength, ratio)
                if not is_signal(conf, floor=0.55, module="ssti"):
                    continue

                sev = "critical" if strength >= 0.9 else "high"
                findings.append({
                    "type": "ssti_confirmed",
                    "severity": sev,
                    "param": name,
                    "payload": payload,
                    "expected": expected,
                    "engine_hint": engine,
                    "verify_hits": hits,
                    "confidence": conf,
                })
                print(f"  ✓ SSTI ({engine}): {payload} → {expected}")
                logger.finding("ssti", sev,
                               f"{name}={payload} → {expected} ({engine})")
                break  # одного payload'а достаточно на param

        print()
        print(f"[ssti v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "probes_active": len(active_probes),
        }
