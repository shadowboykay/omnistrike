"""bloodhound — BloodHound data collection checklist"""
from pathlib import Path

class Bloodhound:
    def run(self, session, logger):
        steps = [
            "# install: pip install bloodhound",
            "# or use SharpHound.exe on Windows targets",
            f"bloodhound-python -u USER -p PASSWORD -d DOMAIN -ns {session.target} -c All",
            "# import to BloodHound GUI",
            "# queries: 'Shortest Paths to Domain Admins', 'Kerberoastable Users', 'Unconstrained Delegation'",
        ]
        print("[bloodhound] commands:")
        for s in steps: print(f"  {s}")
        out = Path("reports") / "bloodhound_commands.txt"
        out.parent.mkdir(exist_ok=True)
        out.write_text("\n".join(steps))
        return {"steps": steps}
