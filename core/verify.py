"""verify — confidence-based signal verification to kill false positives.

Каждый модуль должен:
  1. Снять baseline (N сэмплов одного и того же «нормального» запроса)
  2. Сделать инъекцию
  3. Повторить инъекцию M раз (verify)
  4. Оценить confidence и отбросить всё ниже порога

Идея: интернет шумный — длина ответа колеблется на csrf-токенах,
датах в футере, CDN-заголовках. Одиночный сигнал почти всегда ложь.
"""

from collections import Counter


def median(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return 0
    xs = sorted(xs)
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def _sig(resp):
    """Универсальный слепок ответа."""
    if resp is None:
        return None
    body = getattr(resp, "text", "") or ""
    return {
        "status": getattr(resp, "status_code", 0),
        "len": len(body),
        "hash": hash(body),
        "body": body,
        "headers": dict(getattr(resp, "headers", {}) or {}),
    }


def baseline(make_request, n=3, delay=0.1):
    """
    Снимает baseline — N нормальных запросов.
    make_request: callable без аргументов, возвращает response-объект.
    """
    import time
    samples = []
    for _ in range(n):
        s = _sig(make_request())
        if s:
            samples.append(s)
        time.sleep(delay)
    if not samples:
        return None

    return {
        "status": median([s["status"] for s in samples]),
        "len": median([s["len"] for s in samples]),
        "hash": samples[len(samples) // 2]["hash"],
        "body": samples[0]["body"],
        "samples": samples,
        "len_spread": max(s["len"] for s in samples) - min(s["len"] for s in samples),
        "status_all_same": len(set(s["status"] for s in samples)) == 1,
    }


def verify(make_request, predicate, n=2, delay=0.15):
    """
    Повторяет make_request N раз, считает сколько раз predicate(sample) == True.
    Возвращает hits / n.
    """
    import time
    hits = 0
    total = 0
    for _ in range(n):
        s = _sig(make_request())
        if s is None:
            continue
        total += 1
        if predicate(s):
            hits += 1
        time.sleep(delay)
    if total == 0:
        return 0.0, 0
    return hits / total, hits


def confidence(signal_strength, verify_ratio, baseline=None, sample=None,
               floor=0.55):
    """
    signal_strength ∈ [0,1]:
        1.0 — уникальная сигнатура (например точная строка ошибки СУБД)
        0.7 — устойчивый сдвиг поведения (auth bypass, 302 на другой Location)
        0.4 — length delta в пределах спреда baseline
    verify_ratio ∈ [0,1] — доля подтверждённых повторов.
    Возвращает confidence ∈ [0,1]. Всё ниже floor — мусор.
    """
    conf = signal_strength * (0.6 + 0.4 * verify_ratio)

    # штраф за шумную длину
    if baseline and sample:
        spread = baseline.get("len_spread", 0)
        delta = abs(sample["len"] - baseline["len"])
        # если дельта меньше шума baseline — она не значит ничего
        if delta <= max(spread, 20):
            conf *= 0.4

    # штраф за 5xx без сигнатуры
    if sample and sample.get("status", 0) >= 500 and signal_strength < 0.9:
        conf *= 0.5

    return round(min(conf, 1.0), 3)


def is_signal(conf, floor=0.55):
    return conf >= floor


def looks_like_soft_404(baseline_res, sample):
    """Возвращает True если sample неотличим от baseline (soft 404)."""
    if not baseline_res or not sample:
        return False
    # одинаковый статус и почти одинаковая длина
    if sample["status"] == baseline_res["status"]:
        spread = max(baseline_res.get("len_spread", 0), 50)
        if abs(sample["len"] - baseline_res["len"]) <= spread:
            return True
    return False


def random_token(n=16):
    """Случайный токен для wildcard-проверок (subdomain brute, dir brute)."""
    import secrets, string
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))
