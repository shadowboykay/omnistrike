"""smb_enum — SMB share/user enumeration (null session, guest)"""
from core.http import HttpClient
import subprocess

class SmbEnum:
    def run(self, session, logger):
        host = session.target.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
        print(f"[smb_enum] {host}")

        cmds = {
            "shares": f"smbclient -L //{host}/ -N",
            "users":  f"enum4linux -U {host}",
            "shares_enum4linux": f"enum4linux -S {host}",
            "nmap_smb": f"nmap -p 445 --script smb-enum-shares,smb-enum-users {host}",
        }
        results = {}
        for name, cmd in cmds.items():
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                if out.stdout.strip():
                    results[name] = out.stdout[:2000]
                    print(f"  {name}: {len(out.stdout)} bytes")
                    if "sharename" in out.stdout.lower() or "disk" in out.stdout.lower():
                        logger.finding("smb_shares","high",f"{host} shares accessible")
                else:
                    print(f"  {name}: no output")
            except FileNotFoundError:
                print(f"  {name}: tool not found")
                continue
            except Exception as e:
                print(f"  {name}: {e}")
        return results
