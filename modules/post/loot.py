"""loot — collect files of interest from a target host (via existing access)"""
import os
from pathlib import Path

LOOT_PATHS = [
    "/etc/passwd","/etc/shadow","/etc/hosts","/etc/hostname",
    "/etc/ssh/sshd_config","/root/.ssh/id_rsa","/root/.ssh/authorized_keys",
    "/root/.bash_history","/root/.aws/credentials","/root/.docker/config.json",
    "/root/.kube/config","/root/.git-credentials","/root/.netrc",
    "/var/log/auth.log","/var/log/secure","/var/log/syslog",
    "/var/www/html/.env","/var/www/html/wp-config.php","/var/www/html/config.php",
    "/var/www/html/.git/config",
    "/proc/self/environ","/proc/self/cmdline",
]

class Loot:
    def run(self, session, logger):
        out_dir = Path("loot"); out_dir.mkdir(exist_ok=True)
        print(f"[loot] target list: {len(LOOT_PATHS)} files")
        for p in LOOT_PATHS:
            print(f"  {p}")
        # actual collection depends on how you have access — LFI, shell, etc.
        # this module documents the target list and provides a save path
        (out_dir / "targets.txt").write_text("\n".join(LOOT_PATHS))
        logger.info("loot_targets_saved", path=str(out_dir / "targets.txt"))
        return {"targets": LOOT_PATHS, "output_dir": str(out_dir)}
