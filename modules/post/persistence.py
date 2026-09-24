"""persistence — persistence mechanism checker (linux/windows/macos)"""
from core.http import HttpClient

class Persistence:
    def run(self, session, logger):
        # purely informational — describes common persistence vectors
        vectors = {
            "linux": [
                "crontab -e", "@reboot /tmp/x",
                "/etc/cron.d/", "/etc/systemd/system/*.service",
                "~/.bashrc", "~/.profile", "~/.bash_logout",
                "/etc/rc.local", "~/.config/autostart/",
                "~/.ssh/authorized_keys",
                "/etc/ld.so.preload",
                "LD_PRELOAD in env",
            ],
            "windows": [
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\...\\Run",
                "Task Scheduler (schtasks /create)",
                "WMI Event Subscription",
                "Services (sc create)",
                "Startup folder",
                "DLL search order hijacking",
            ],
            "macos": [
                "~/Library/LaunchAgents/",
                "/Library/LaunchDaemons/",
                "login items",
                "cron (via launchd)",
            ],
        }
        for os, items in vectors.items():
            print(f"[persistence:{os}]")
            for i in items:
                print(f"  {i}")
                logger.finding("persistence_vector","info",f"{os}: {i}")
        return {"vectors": vectors}
