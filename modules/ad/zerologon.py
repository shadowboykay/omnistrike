"""zerologon — CVE-2020-1472 Zerologon probe (Netlogon)"""
from core.http import HttpClient
import socket, os

class Zerologon:
    def run(self, session, logger):
        host = session.target.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
        print(f"[zerologon] probing {host}:445")

        # basic port check
        try:
            s = socket.create_connection((host, 445), timeout=5)
            s.close()
            print("  port 445 open")
        except Exception:
            print("  port 445 closed"); return {}

        # check if DC via netlogon
        print("  see: https://github.com/dirkjanm/CVE-2020-1472")
        print("  probe: python cve-2020-1472-exploit.py <netbios-name> <dc-ip>")
        print("  detect: nmap -p 445 --script smb-vuln-zerologon " + host)
        logger.finding("zerologon_probe","info",f"{host} port 445 open")
        return {"host": host, "port_open": True}
