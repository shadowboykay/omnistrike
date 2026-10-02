"""cors v2 — CORS misconfiguration with subdomain + null-origin + ACAC checks.

Сигналы (по убыванию severity):
  1. wildcard_with_credentials:  ACAO=*  +  ACAC=true   (сломанная конфига)
  2. arbitrary_reflect_creds:    ACAO=evil + ACAC=true  (любой домен → сессия утечёт)
  3. null_origin_reflect:        ACAO=null + ACAC=true  (iframe sandbox → CSRF)
  4. subdomain_trick:            ACAO=target.evil       (regex-подстрока)
  5. suffix_trick:               ACAO=eviltarget.com    (regex без \b)
  6. arbitrary_reflect:          ACAO=evil              (reflection без creds)
  7. protocol_downgrade:         http когда target https (mixed content)

Используем 8+ origin-форм, включая URL-encoded и IDN.
"""
from urllib.parse import urlparse
from core.http import HttpClient
from core.verify import verify, confidence, is_signal
from core.waf_bypass import is_blocked


def _origin_forms(host):
    """Список злонамеренных Origin для проверки всех типов reflection."""
    base = host or "target.example"
    return [
        ("arbitrary_reflect",     "https://attacker-" + __import__("secrets").token_hex(3) + ".example"),
        ("null_origin",           "null"),
        ("subdomain_prefix",      f"https://{base}.evil.example"),         # base.evil
        ("subdomain_suffix",      f"https://evil.{base}"),                 # evil.base
        ("suffix_no_dot",         f"https://evil{base}"),                  # evilbase
        ("prefix_no_dot",         f"https://{base}evil.example"),          # baseevil.example
        ("http_downgrade",        f"http://{base}"),
        ("port_trick",            f"https://{base}:1337"),
        ("userinfo_trick",        f"https://{base}@evil.example"),
        ("case_swap",             f"HTTPS://{base.upper()}"),
        ("url_encoded",           f"https://{base}%2Eevil.example"),
        ("backslash",             f"https://{base}\\@evil.example"),
    ]


def _classify(origin_label, origin, acao, acac):
    """
    Возвращает (signal_name, severity, strength) или None.
    """
    if not acao:
        return None

    acao_low = acao.strip().lower()
    origin_low = origin.strip().lower()
    has_creds = acac.strip().lower() == "true"

    # 1. wildcard + creds — сломанная конфига (по спеке ACAO: * + ACAC: true не работает, но некоторые ставят)
    if acao_low == "*" and has_creds:
        return "wildcard_with_credentials", "high", 0.95

    # 2. отражение нашего evil-origin
    if acao_low == origin_low or acao_low == origin_low.rstrip("/"):
        if origin_label == "null_origin":
            if has_creds:
                return "null_origin_with_credentials", "critical", 0.95
            return "null_origin_reflected", "medium", 0.7
        if origin_label in ("subdomain_prefix", "subdomain_suffix",
                            "suffix_no_dot", "prefix_no_dot"):
            if has_creds:
                return f"{origin_label}_with_credentials", "critical", 0.95
            return f"{origin_label}_reflected", "medium", 0.75
        if origin_label == "http_downgrade":
            return "protocol_downgrade_reflected", "medium", 0.7
        if origin_label == "port_trick":
            if has_creds:
                return "port_trick_with_credentials", "high", 0.85
            return "port_trick_reflected", "low", 0.6
        if origin_label == "userinfo_trick":
            return "userinfo_trick_reflected", "high", 0.85
        if origin_label in ("case_swap", "url_encoded", "backslash"):
            return f"{origin_label}_reflected", "low", 0.6
        # обычный arbitrary reflect
        if has_creds:
            return "arbitrary_reflect_with_credentials", "critical", 0.95
        return "arbitrary_reflect", "medium", 0.7

    # 3. ACAO совпадает с нашим поддоменом, но не отражает полностью
    # (например ACAO=https://target.example для origin=evil.target.example)
    return None


class Cors:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        host = u.hostname or "target.example"

        # === baseline: без Origin ===
        try:
            base_r = http.get(target)
            base_acao = (base_r.headers.get("Access-Control-Allow-Origin", "") if base_r else "")
        except Exception:
            base_acao = ""

        print(f"[cors v2] target: {target}")
        print(f"[cors v2] baseline ACAO: {base_acao[:60] or '(none)'}")

        findings = []
        seen_signals = set()  # не дублировать один и тот же тип

        for label, origin in _origin_forms(host):
            try:
                r = http.get(target, headers={"Origin": origin})
            except Exception:
                continue
            if not r:
                continue
            if is_blocked(r):
                continue

            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            classified = _classify(label, origin, acao, acac)
            if not classified:
                continue
            signal_name, severity, strength = classified

            # дедупликация — один тип сигнала достаточно
            if signal_name in seen_signals:
                continue

            # === verify: повторить ×2 ===
            def rep():
                try:
                    return http.get(target, headers={"Origin": origin})
                except Exception:
                    return None

            def predicate(s):
                ref = s["headers"].get("Access-Control-Allow-Origin", "").strip().lower()
                creds = s["headers"].get("Access-Control-Allow-Credentials", "").strip().lower()
                return (ref == origin.strip().lower()
                        or (ref == "*" and creds == "true"))

            ratio, hits = verify(rep, predicate, n=2, delay=0.15)

            conf = confidence(strength, ratio)
            if not is_signal(conf, floor=0.55, module="cors"):
                continue

            seen_signals.add(signal_name)
            findings.append({
                "type": signal_name,
                "severity": severity,
                "origin": origin,
                "acao": acao,
                "acac": acac,
                "verify_hits": hits,
                "confidence": conf,
            })
            print(f"  ✓ {signal_name}: Origin={origin} → ACAO={acao} ACAC={acac}")
            logger.finding(f"cors_{signal_name}", severity,
                           f"Origin={origin} ACAO={acao} ACAC={acac} conf={int(conf*100)}")

        print(f"[cors v2] findings: {len(findings)}")
        return {"findings": findings}
