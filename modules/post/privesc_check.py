"""privesc_check — linux privilege escalation checklist"""
from pathlib import Path

CHECKS = {
    "suid":          "find / -perm -4000 -type f 2>/dev/null",
    "sudo_nopass":   "sudo -n -l 2>/dev/null",
    "writable_passwd":"ls -la /etc/passwd /etc/shadow",
    "cron":          "cat /etc/crontab; ls -la /etc/cron.*",
    "docker_group":  "id | grep docker",
    "kernels":       "uname -a; cat /etc/*release",
    "capabilities":  "getcap -r / 2>/dev/null",
    "nfs":           "cat /etc/exports",
    "env":           "env",
    "history":       "cat ~/.bash_history",
    "world_writable":"find / -writable -type d 2>/dev/null",
    "package_ver":   "cat /etc/debian_version; rpm -qa | head",
    "pkexec_version":"pkexec --version",
    "polkit_version":"dpkg -l | grep policykit",
}

class PrivescCheck:
    def run(self, session, logger):
        out = Path("reports") / "privesc_checklist.txt"
        out.parent.mkdir(exist_ok=True)
        lines = ["# Linux privilege escalation checklist", ""]
        for name, cmd in CHECKS.items():
            lines.append(f"## {name}")
            lines.append(f"  $ {cmd}")
            lines.append("")
            print(f"  [{name}] {cmd}")
        out.write_text("\n".join(lines))
        logger.info("privesc_checklist", path=str(out))
        return {"checks": CHECKS, "file": str(out)}
