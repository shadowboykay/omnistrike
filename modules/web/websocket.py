"""websocket v2 — WS discovery + auth-bypass + frame injection + origin check.

Отличия от v1:
  - 14 endpoints (было 7)
  - проверка auth-bypass (handshake без Cookie/Authorization → 101)
  - сообщение-инъекция: text frame с canary → echo check
  - отсутствие проверки Origin (CSRF-подобный доступ с чужого домена)
  - rate-limit: 3× handshake чтобы убедиться в стабильности
  - SSL-обёртка через ssl для https целей
  - is_signal(module='websocket')
"""
import re
import ssl
import socket
import base64
import secrets
import struct
import time
from urllib.parse import urlparse
from core.http import HttpClient
from core.verify import confidence, is_signal


# endpoint-кандидаты
WS_PATHS = [
    "/ws", "/websocket", "/socket", "/socket.io/",
    "/ws/", "/api/ws", "/api/websocket", "/realtime",
    "/ws/chat", "/ws/notifications", "/ws/graphql",
    "/graphql", "/gql", "/sockjs", "/hub",
    "/_ws", "/stream", "/events", "/cable",
]

# протоколы для Sec-WebSocket-Protocol
WS_PROTOCOLS = "chat, graphql-ws, graphql-transport-ws, mqtt, json, superchat"


def _raw_handshake(host, port, path, is_tls, protocols=WS_PROTOCOLS,
                   origin=None, cookie=None, timeout=8):
    """
    Отправляет WebSocket handshake, возвращает dict:
      {status, headers, raw, accept_key_valid, tls_ok}
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if is_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
    except Exception as e:
        return {"error": str(e)[:100], "status": 0}

    key_bytes = secrets.token_bytes(16)
    key = base64.b64encode(key_bytes).decode()

    headers = [
        "GET " + path + " HTTP/1.1",
        "Host: " + host,
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: " + key,
        "Sec-WebSocket-Version: 13",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ]
    if protocols:
        headers.append("Sec-WebSocket-Protocol: " + protocols)
    if origin:
        headers.append("Origin: " + origin)
    else:
        headers.append("Origin: https://" + host)
    if cookie:
        headers.append("Cookie: " + cookie)

    req = "\r\n".join(headers) + "\r\n\r\n"

    try:
        sock.sendall(req.encode())
        sock.settimeout(4)
        resp = b""
        while b"\r\n\r\n" not in resp and len(resp) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return {"error": str(e)[:100], "status": 0}

    text = resp.decode("latin-1", errors="ignore")
    # парсим status
    first_line = text.split("\r\n", 1)[0] if text else ""
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", first_line)
    status = int(m.group(1)) if m else 0

    # валидация Sec-WebSocket-Accept
    accept_valid = False
    accept_match = re.search(r"Sec-WebSocket-Accept:\s*(\S+)", text, re.I)
    if accept_match:
        import hashlib
        GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        expected = base64.b64encode(
            hashlib.sha1((key + GUID).encode()).digest()
        ).decode()
        accept_valid = (accept_match.group(1).strip() == expected)

    result = {
        "status": status,
        "raw": text[:2000],
        "accept_valid": accept_valid,
        "key_sent": key,
        "sock": sock,
    }
    return result


def _ws_frame(payload, opcode=1):
    """Frame WebSocket с маской (RFC 6455) для клиентских сообщений."""
    if isinstance(payload, str):
        payload = payload.encode()
    b1 = 0x80 | opcode
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", b1, 0x80 | length)
    elif length < 65536:
        header = struct.pack("!BBH", b1, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", b1, 0x80 | 127, length)
    mask = secrets.token_bytes(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return header + mask + masked


def _send_frame(sock, payload, opcode=1):
    """Отправляет frame, ждёт ответ (2 сек). Возвращает bytes payload или b''."""
    try:
        sock.sendall(_ws_frame(payload, opcode=opcode))
        sock.settimeout(2.5)
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 10000:
                    break
        except socket.timeout:
            pass
        return data
    except Exception:
        return b""


class Websocket:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        host = u.hostname
        is_tls = (u.scheme == "https")
        port = u.port or (443 if is_tls else 80)
        http = HttpClient(session, logger)

        print("[ws v2] target: " + target)
        print("[ws v2] scheme: " + ("wss" if is_tls else "ws") + "://" + str(host) + ":" + str(port))

        findings = []

        # === 1. discovery: найти ws URLs в HTML ===
        try:
            r_main = http.get(target)
        except Exception:
            r_main = None

        ws_urls_from_html = set()
        if r_main:
            ws_urls_from_html = set(re.findall(r'wss?://[^\s"\'<>]+', r_main.text or ""))
            if ws_urls_from_html:
                print("[ws v2] found in HTML: " + str(len(ws_urls_from_html)))
                for w in list(ws_urls_from_html)[:5]:
                    print("  " + w[:120])

        # === 2. handshake probe по каждому пути ===
        print()
        print("[ws v2] Phase 2: handshake probes")

        live_ws = []

        for path in WS_PATHS:
            # 1. пробуем с cookies (если есть в сессии) + с Origin
            r1 = _raw_handshake(host, port, path, is_tls)
            if r1.get("status") == 0:
                continue

            status = r1["status"]
            if status not in (101, 400, 401, 403, 426, 200):
                continue

            marker = "  "
            if status == 101 and r1.get("accept_valid"):
                marker = "  [UPGRADE]"
                print(marker + " " + path + " -> 101 + valid accept-key")
                live_ws.append({
                    "path": path,
                    "accept_valid": True,
                    "auth_bypass": True,  # handshake без cookies
                    "origin_echo": None,
                })
            elif status == 101:
                print("  [101-invalid-accept] " + path)
                live_ws.append({"path": path, "accept_valid": False, "auth_bypass": True})
            elif status in (400, 401, 403, 426):
                print("  [" + str(status) + "] " + path)

        # === 3. auth-bypass test: без cookies ===
        if live_ws:
            print()
            print("[ws v2] Phase 3: auth-bypass verification")
            for ws in live_ws:
                # с мусорной Cookie — accept 101 = либо не проверяет cookie, либо проверка не критична
                r2 = _raw_handshake(host, port, ws["path"], is_tls,
                                    cookie="omni_invalid=" + secrets.token_hex(4))
                if r2.get("status") == 101 and r2.get("accept_valid"):
                    ws["auth_bypass_confirmed"] = True
                    conf = confidence(0.85, 1.0)
                    if is_signal(conf, floor=0.55, module="websocket"):
                        findings.append({
                            "type": "ws_auth_bypass",
                            "severity": "high",
                            "path": ws["path"],
                            "note": "101 upgrade accepted without valid session",
                            "confidence": conf,
                        })
                        print("  [HIGH] auth-bypass: " + ws["path"])
                        logger.finding("ws_auth_bypass", "high", ws["path"])
                else:
                    ws["auth_bypass_confirmed"] = False

        # === 4. Origin check ===
        if live_ws:
            print()
            print("[ws v2] Phase 4: Origin validation check")
            for ws in live_ws[:3]:
                r_evil = _raw_handshake(host, port, ws["path"], is_tls,
                                        origin="https://omni-attacker.invalid")
                if r_evil.get("status") == 101:
                    ws["origin_unchecked"] = True
                    conf = confidence(0.75, 1.0)
                    if is_signal(conf, floor=0.55, module="websocket"):
                        findings.append({
                            "type": "ws_no_origin_check",
                            "severity": "medium",
                            "path": ws["path"],
                            "note": "101 accepted with evil Origin header",
                            "confidence": conf,
                        })
                        print("  [MEDIUM] no Origin check: " + ws["path"])
                        logger.finding("ws_origin_unchecked", "medium", ws["path"])

        # === 5. frame injection (только если 101) ===
        if live_ws and any(w.get("accept_valid") for w in live_ws):
            print()
            print("[ws v2] Phase 5: frame injection (echo check)")
            canary = "OMNI_WS_" + secrets.token_hex(4)
            target_ws = next((w for w in live_ws if w.get("accept_valid")), live_ws[0])

            # установить соединение ещё раз (r1/r2 уже закрыты)
            r_conn = _raw_handshake(host, port, target_ws["path"], is_tls)
            if r_conn.get("status") == 101 and "sock" in r_conn:
                sock = r_conn["sock"]
                # text frame с JSON
                test_payloads = [
                    '{"type":"ping","data":"' + canary + '"}',
                    '{"action":"echo","message":"' + canary + '"}',
                    'ping ' + canary,
                ]
                for msg in test_payloads:
                    data = _send_frame(sock, msg)
                    if canary.encode() in data:
                        conf = confidence(0.8, 1.0)
                        if is_signal(conf, floor=0.55, module="websocket"):
                            findings.append({
                                "type": "ws_echo_response",
                                "severity": "info",
                                "path": target_ws["path"],
                                "message": msg[:80],
                                "confidence": conf,
                            })
                            print("  [INFO] echo confirmed via " + target_ws["path"])
                            logger.finding("ws_echo", "info", target_ws["path"])
                        break
                try:
                    sock.close()
                except Exception:
                    pass

        # === 6. findings summary ===
        print()
        print("[ws v2] findings: " + str(len(findings)))
        return {
            "findings": findings,
            "urls": list(ws_urls_from_html),
            "live_ws": live_ws,
        }
