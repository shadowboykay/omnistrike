"""mobile_traffic — Android app traffic interception setup guide"""
from pathlib import Path

class MobileTraffic:
    def run(self, session, logger):
        lines = [
            "# Android traffic interception setup",
            "",
            "## 1. Proxy setup",
            "- Run mitmproxy/burp on host (port 8080)",
            "- Android WiFi → Proxy → manual → host:8080",
            "",
            "## 2. Install CA cert",
            "- Visit http://mitm.it/ on device → install CA",
            "- Android 7+: system CA required for user apps",
            "  adb push cert.pem /system/etc/security/cacerts/",
            "  adb shell chmod 644 /system/etc/security/cacerts/*",
            "",
            "## 3. SSL pinning bypass (frida)",
            "- frida-server on device (root)",
            "  frida -U -f com.target.app -l ssl_bypass.js",
            "- use template from modules/mobile/frida_hook.py",
            "",
            "## 4. Transparent proxy (no WiFi proxy)",
            "- iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 8080",
            "- iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 8080",
            "",
            "## 5. Root detection bypass",
            "- MagiskHide / DenyList",
            "- frida hook: rootbeer, safetynet, play integrity",
        ]
        out = Path("reports") / "mobile_traffic_setup.md"
        out.parent.mkdir(exist_ok=True)
        out.write_text("\n".join(lines))
        for l in lines[:15]: print(l)
        print(f"... (full: {out})")
        logger.info("mobile_traffic", path=str(out))
        return {"path": str(out)}
