"""websocket_fuzz — WebSocket endpoint discovery + message injection fuzz"""
import socket, base64, os, re
from urllib.parse import urlparse
from core.http import HttpClient

WS_PATHS = ["/ws", "/websocket", "/socket", "/socket.io/", "/ws/", "/api/ws",
            "/realtime", "/live", "/stream", "/events", "/ws/v1", "/api/socket"]

# fuzz payloads for WS messages
FUZZ = [
    '{"type":"ping"}',
    '{"action":"info"}',
    '{"cmd":"id"}',
    '{"message":"<script>alert(1)</script>"}',
    '{"user":"admin"}',
    '{"token":""}',
    "' OR '1'='1",
    '../'*10 + 'etc/passwd',
    '{{7*7}}',
    '$(id)',
]


def _ws_handshake(host, port, path, timeout=5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        s.sendall(req.encode())
        s.settimeout(timeout)
        resp = b""
        try:
            resp = s.recv(2048)
        except socket.timeout:
            pass
        s.close()
        return resp.decode("latin1", errors="ignore")
    except Exception as e:
        return f"ERROR: {e}"


class WebsocketFuzz:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)

        http = HttpClient(session, logger)
        findings = []

        # 1. discover WS endpoints in HTML/JS
        r = http.get(target)
        if r:
            for m in re.findall(r'wss?://[^\s"\'<>]+', r.text):
                print(f"  [+] ws url in page: {m[:80]}")
                findings.append({"url": m, "source": "page", "severity": "info"})
                logger.finding("ws_url", "info", m[:80])

        # 2. probe common paths
        for path in WS_PATHS:
            resp = _ws_handshake(host, port, path)
            first_line = resp.split("\r\n")[0] if resp else ""
            if "101" in first_line:
                print(f"  [!] WS accepts: {path}")
                findings.append({"path": path, "type": "upgrade_accept", "severity": "medium"})
                logger.finding("websocket", "medium", path)

                # try origin bypass
                for evil_origin in ["http://evil.attacker.example", "null", "*"]:
                    resp2 = _ws_handshake_origin(host, port, path, evil_origin)
                    if "101" in (resp2.split("\r\n")[0] if resp2 else ""):
                        print(f"  [!] origin bypass: {evil_origin}")
                        findings.append({"path": path, "type": "origin_bypass",
                                         "origin": evil_origin, "severity": "high"})
                        logger.finding("ws_origin_bypass", "high", f"{path} from {evil_origin}")
            elif "400" in first_line or "426" in first_line:
                print(f"  · {path}: {first_line[:60]}")

        print(f"[websocket_fuzz] total: {len(findings)}")
        return {"findings": findings}


def _ws_handshake_origin(host, port, path, origin, timeout=5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Origin: {origin}\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        s.sendall(req.encode())
        s.settimeout(timeout)
        resp = b""
        try: resp = s.recv(2048)
        except socket.timeout: pass
        s.close()
        return resp.decode("latin1", errors="ignore")
    except Exception as e:
        return f"ERROR: {e}"
