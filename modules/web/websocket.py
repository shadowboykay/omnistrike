"""websocket — WebSocket endpoint discovery + basic fuzzing"""
import re, socket, base64, os
from core.http import HttpClient
from urllib.parse import urlparse

class Websocket:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        r = http.get(target)
        if not r: return {}
        ws_urls = set(re.findall(r'wss?://[^\s"\'<>]+', r.text))
        # common paths
        for ep in ["/ws","/websocket","/socket","/socket.io","/ws/","/api/ws","/realtime"]:
            r2 = http.get(target.rstrip("/") + ep)
            if r2 and r2.status_code in (101, 200, 400, 426):
                ws_urls.add(target.replace("http","ws").rstrip("/") + ep)
                print(f"  [+] ws candidate: {ep} ({r2.status_code})")
                logger.finding("websocket","info",ep)

        for w in ws_urls:
            print(f"  [+] {w}")
            logger.finding("websocket_url","info",w)

        # try upgrade handshake
        u = urlparse(target)
        host = u.hostname; port = u.port or (443 if u.scheme == "https" else 80)
        findings = []
        for path in ["/ws","/websocket","/socket"]:
            try:
                s = socket.create_connection((host, port), timeout=5)
                key = base64.b64encode(os.urandom(16)).decode()
                handshake = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                )
                s.sendall(handshake.encode())
                s.settimeout(3)
                resp = s.recv(2048).decode(errors="ignore")
                s.close()
                if "101" in resp.split("\r\n")[0]:
                    print(f"  [!] WS accepts: {path}")
                    logger.finding("websocket_accept","medium",path)
                    findings.append(path)
            except Exception: pass

        print(f"[websocket] {len(ws_urls)} urls, {len(findings)} accepting upgrade")
        return {"urls": list(ws_urls), "accepting": findings}
