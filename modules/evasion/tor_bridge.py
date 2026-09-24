"""tor_bridge — Tor SOCKS5 setup checklist (obfuscated bridges)"""
from pathlib import Path

class TorBridge:
    def run(self, session, logger):
        steps = [
            "# Termux Tor setup",
            "pkg install tor -y",
            "",
            "# configure obfs4 bridge",
            "cat > $PREFIX/etc/tor/torrc << 'EOT'",
            "  SocksPort 9050",
            "  Bridge obfs4 <ip:port> <fingerprint> cert=<cert> iat-mode=0",
            "  UseBridges 1",
            "EOT",
            "",
            "# start",
            "tor &",
            "",
            "# route requests through tor",
            f"python omni.py run web sqli --target {session.target} --proxy socks5://127.0.0.1:9050",
        ]
        out = Path("reports") / "tor_bridge_setup.sh"
        out.parent.mkdir(exist_ok=True)
        out.write_text("\n".join(steps))
        for l in steps: print(l)
        logger.info("tor_setup", path=str(out))
        return {"steps": steps}
