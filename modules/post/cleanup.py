"""cleanup — post-op cleanup checklist (logs, files, history)"""
from pathlib import Path

ITEMS = [
    ("linux_logs",  "/var/log/auth.log, /var/log/secure, ~/.bash_history, ~/.zsh_history"),
    ("linux_files", "shred -u /tmp/payload; rm -rf /tmp/omnistrike"),
    ("windows_logs","wevtutil cl Security; wevtutil cl System; wevtutil cl Application"),
    ("windows_files","del /f /q C:\\Windows\\Temp\\x.exe"),
    ("registry",    "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v X /f"),
    ("services",    "sc delete ServiceName"),
    ("scheduled",   "schtasks /delete /tn TaskName /f"),
    ("artifacts",   "chmod 000 /var/log/... ; history -c"),
]

class Cleanup:
    def run(self, session, logger):
        out = Path("reports") / "cleanup_checklist.txt"
        out.parent.mkdir(exist_ok=True)
        lines = ["# Post-op cleanup checklist", ""]
        for name, action in ITEMS:
            lines.append(f"## {name}\n  {action}\n")
            print(f"  [{name}] {action}")
        out.write_text("\n".join(lines))
        return {"items": ITEMS, "file": str(out)}
