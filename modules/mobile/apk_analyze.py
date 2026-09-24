"""apk_analyze — static APK analysis: permissions, urls, secrets"""
import re, zipfile
from pathlib import Path

DANGEROUS_PERMS = [
    "android.permission.READ_SMS","android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS","android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG","android.permission.WRITE_CALL_LOG",
    "android.permission.CAMERA","android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION","android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE","android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW","android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS","android.permission.BIND_ACCESSIBILITY_SERVICE",
]

SECRET_RE = {
    "aws_key":   re.compile(r"AKIA[0-9A-Z]{16}"),
    "google":    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "firebase":  re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"),
    "jwt":       re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "http_url":  re.compile(rb"https?://[a-zA-Z0-9._\-]+"),
}

class ApkAnalyze:
    def run(self, session, logger):
        apk = Path(session.target)
        if not apk.is_file():
            print(f"[apk] not a file: {apk}"); return {}
        print(f"[apk] {apk.name} ({apk.stat().st_size} bytes)")

        findings = {"permissions": [], "urls": set(), "secrets": []}
        try:
            with zipfile.ZipFile(apk) as z:
                names = z.namelist()
                print(f"  entries: {len(names)}")

                # AndroidManifest is binary in release, but strings extraction works
                for n in names:
                    if n == "AndroidManifest.xml":
                        data = z.read(n)
                        # crude permission extraction from binary XML
                        for perm in DANGEROUS_PERMS:
                            if perm.encode() in data:
                                findings["permissions"].append(perm)
                                print(f"  [!] perm: {perm}")
                                logger.finding("apk_permission","high",perm)

                # scan classes.dex / resources.arsc for strings
                for n in names:
                    if n.endswith(".dex") or n.endswith(".so"):
                        try:
                            data = z.read(n)
                        except Exception:
                            continue
                        for m in SECRET_RE["http_url"].findall(data):
                            try: findings["urls"].add(m.decode())
                            except Exception: pass

                for name, pat in SECRET_RE.items():
                    if name == "http_url": continue
                    for n in names:
                        try:
                            data = z.read(n)
                        except Exception:
                            continue
                        for m in pat.findall(data.decode("latin1", errors="ignore")):
                            findings["secrets"].append({"type":name,"value":m[:80]})
                            print(f"  [!] {name}: {m[:60]}")
                            logger.finding("apk_secret","high",f"{name}: {m[:60]}")

        except zipfile.BadZipFile:
            print("[apk] not a valid zip/apk"); return {}

        findings["urls"] = sorted(findings["urls"])[:200]
        print(f"[apk] {len(findings['permissions'])} perms, {len(findings['urls'])} urls, {len(findings['secrets'])} secrets")
        return findings
