"""tor_auto — check Tor availability, use socks5://127.0.0.1:9050"""
from core.http import HttpClient
import subprocess, socket, time


def tor_running(host="127.0.0.1", port=9050):
    try:
        s = socket.create_connection((host, port), timeout=2)
        s.close()
        return True
    except Exception:
        return False


class TorAuto:
    def run(self, session, logger):
        print("[tor_auto] checking...")

        if not tor_running():
            print("  ✗ Tor not running (127.0.0.1:9050)")
            print()
            print("  Установка в Termux:")
            print("    pkg install tor")
            print("    tor &")
            print()
            print("  Проверка: " + "curl --socks5 127.0.0.1:9050 https://check.torproject.org/")
            return {"tor": False}

        print("  ✓ Tor SOCKS5 active (127.0.0.1:9050)")

        # check our IP via Tor
        try:
            from core.session import Session
            sub = Session(target="https://check.torproject.org/api/ip",
                          proxy="socks5://127.0.0.1:9050", timeout=20)
            h = HttpClient(sub, logger)
            r = h.get("https://check.torproject.org/api/ip")
            if r and r.status_code == 200:
                import json
                try:
                    data = r.json()
                    is_tor = data.get("IsTor", False)
                    ip = data.get("IP", "?")
                    print(f"  Tor exit: {ip}, IsTor={is_tor}")
                    logger.finding("tor_check", "info", f"IP={ip} IsTor={is_tor}")
                except Exception:
                    print(f"  raw: {r.text[:200]}")
        except Exception as e:
            print(f"  error: {type(e).__name__}: {e}")

        # run target through Tor
        print()
        print(f"  Target via Tor: {session.target}")
        sub_session = Session(target=session.target, proxy="socks5://127.0.0.1:9050",
                              timeout=25)
        h2 = HttpClient(sub_session, logger)
        r = h2.get(session.target)
        if r:
            print(f"  ✓ Through Tor: {r.status_code} {len(r.content)}b")
            logger.finding("tor_target_access", "info",
                           f"{session.target} {r.status_code}")
        else:
            print(f"  ✗ Through Tor: failed")

        return {"tor": True}
