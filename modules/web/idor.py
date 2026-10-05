"""idor v2 — insecure direct object reference with field comparison."""
import re
import json
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from core.http import HttpClient
from core.verify import confidence, is_signal


# поля, по которым можно опознать ресурс
IDENTIFIABLE_FIELDS = [
    "id", "user_id", "uid", "account_id", "order_id",
    "email", "username", "login", "name", "phone",
    "ssn", "passport", "card", "iban",
]

# endpoint patterns для IDOR
IDOR_PATTERNS = [
    r"/api/users?/(\d+)",
    r"/api/user/(\d+)",
    r"/api/accounts?/(\d+)",
    r"/api/orders?/(\d+)",
    r"/api/items?/(\d+)",
    r"/api/v\d+/users?/(\d+)",
    r"/users?/(\d+)",
    r"/accounts?/(\d+)",
    r"/orders?/(\d+)",
    r"/profile/(\d+)",
    r"/account/(\d+)",
]


def _extract_ids_from_url(url):
    """Возвращает список (id_value, position_start, position_end) в URL."""
    out = []

    u = urlparse(url)
    # в query
    q = parse_qs(u.query)
    for key in ("id", "user", "uid", "account", "pid", "order", "item"):
        if key in q and q[key]:
            val = q[key][0]
            if val.isdigit() and 1 <= len(val) <= 10:
                out.append(("query", key, val))

    # в path
    for pat in IDOR_PATTERNS:
        m = re.search(pat, u.path)
        if m:
            out.append(("path", m.group(0), m.group(1)))
            break
    else:
        # generic: любой digit в path
        m = re.search(r"/(\d{1,10})(?:/|$|\.)", u.path)
        if m:
            out.append(("path", u.path, m.group(1)))

    return out


def _replace_id_in_url(url, kind, key_or_path, old_id, new_id):
    """Заменить ID в URL. Возвращает новый URL."""
    u = urlparse(url)
    if kind == "query":
        q = parse_qs(u.query)
        q[key_or_path] = [str(new_id)]
        new_q = urlencode(q, doseq=True)
        return urlunparse(u._replace(query=new_q))
    else:
        # kind == "path"
        new_path = key_or_path.replace(str(old_id), str(new_id))
        return urlunparse(u._replace(path=new_path))


def _extract_signature(body):
    """Пытаемся извлечь уникальный идентификатор из тела (JSON или HTML)."""
    if not body:
        return None

    # 1. JSON
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            for f in IDENTIFIABLE_FIELDS:
                if f in data and data[f] is not None:
                    return f + "=" + str(data[f])[:60]
        elif isinstance(data, list) and data:
            first = data[0]
            if isinstance(first, dict):
                for f in IDENTIFIABLE_FIELDS:
                    if f in first:
                        return f + "=" + str(first[f])[:60]
    except Exception:
        pass

    # 2. HTML — ищем email
    m = re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body)
    if m:
        return "email=" + m.group(0)

    return None


class Idor:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        print("[idor v2] target: " + target)

        # найти ID
        ids_info = _extract_ids_from_url(target)
        if not ids_info:
            print("[idor v2] no numeric IDs in URL — skip")
            return {"findings": []}

        print("[idor v2] found IDs: " + str(ids_info))

        findings = []

        for kind, key_or_path, old_id_str in ids_info:
            try:
                old_id = int(old_id_str)
            except ValueError:
                continue

            # baseline
            try:
                base_r = http.get(target)
            except Exception:
                continue
            if not base_r or base_r.status_code != 200:
                continue

            base_sig = _extract_signature(base_r.text or "")
            base_status = base_r.status_code
            base_size = len(base_r.content)

            print("[idor v2] baseline: " + str(base_status) + " " + str(base_size) + "b sig=" + str(base_sig))

            # кандидаты
            candidates = []
            for off in (-2, -1, 1, 2, 10, 100, 1000):
                c = old_id + off
                if c > 0:
                    candidates.append(c)

            for cid in candidates:
                new_url = _replace_id_in_url(target, kind, key_or_path, old_id, cid)
                try:
                    r = http.get(new_url)
                except Exception:
                    continue
                if not r or r.status_code != 200:
                    continue

                new_sig = _extract_signature(r.text or "")

                # сигнал: 200 + сигнатура изменилась (чужой ресурс)
                if not new_sig:
                    continue
                if new_sig == base_sig:
                    continue

                # verify ×2
                try:
                    r2 = http.get(new_url)
                except Exception:
                    continue
                if not r2 or r2.status_code != 200:
                    continue
                sig2 = _extract_signature(r2.text or "")
                if sig2 != new_sig:
                    continue

                conf = confidence(0.9, 1.0)
                if not is_signal(conf, floor=0.55, module="idor"):
                    continue

                findings.append({
                    "type": "idor_confirmed",
                    "severity": "high",
                    "url": new_url,
                    "original_id": old_id,
                    "accessed_id": cid,
                    "baseline_sig": base_sig,
                    "accessed_sig": new_sig,
                    "confidence": conf,
                })
                print("  IDOR: id " + str(old_id) + " -> " + str(cid) + " sig_changed")
                logger.finding("idor", "high", new_url + " id " + str(old_id) + "->" + str(cid))
                break

        print()
        print("[idor v2] findings: " + str(len(findings)))
        return {"findings": findings, "ids_found": len(ids_info)}
