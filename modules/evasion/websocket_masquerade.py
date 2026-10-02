"""websocket_masquerade v2 — realistic WebSocket upgrade + frame testing.

v1: один GET с WS headers.
v2:
  - Полный handshake (Sec-WebSocket-Key, Version, Extensions)
  - Правильный Origin
  - Проверка 101 Switching Protocols
  - Отправка WebSocket frames если 101 получен
  - Реальные протоколы: chat, graphql-ws, mqtt, json-ld
  - User-Agent Chrome 124

Использование:
  - Обход WAF, которые по-разному обрабатывают WS vs HTTP
  - Тест WS-эндпоинтов (уязвимости в Upgrade-обработчиках)
  - Проверка поддержки WS-протоколов
"""
import os
import base64
import hashlib
import socket
import struct
import time
from urllib.parse import urlparse
from core.http import HttpClient


# ==== WS-протоколы по типу сервиса ====
WS_PROTOCOLS = {
    "chat":       ["chat", "superchat", "livereload"],
    "graphql":    ["graphql-ws", "graphql-transport-ws"],
    "mqtt":       ["mqtt", "mqttv3.1", "mqttv5.0"],
    "realtime":   ["actioncable", "phoenix", "socket.io", "sockjs"],
    "iot":        ["v12.stomp", "v11.stomp", "wamp.2.json"],
}

# WS-эндпоинты (типовые)
WS_PATHS = ["/ws", "/websocket", "/socket", "/socket.io/", "/ws/chat", "/realtime",
            "/graphql", "/mqtt", "/wss", "/_ws"]


def _make_ws_key():
    """Sec-WebSocket-Key — base64 из 16 случайных байт."""
    return base64.b64encode(os.urandom(16)).decode()


def _ws_frame(payload, opcode=1, masked=True):
    """Создать WebSocket frame (RFC 6455). opcode=1 — text."""
    if isinstance(payload, str):
        payload = payload.encode()
    b1 = 0x80 | opcode  # FIN + opcode
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", b1, (0x80 if masked else 0) | length)
    elif length < 65536:
        header = struct.pack("!BBH", b1, (0x80 if masked else 0) | 126, length)
    else:
        header = struct.pack("!BBQ", b1, (0x80 if masked else 0) | 127, length)
    if masked:
        mask = os.urandom(4)
        masked_payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return header + mask + masked_payload
    return header + payload


def _parse_ws_frame(data):
    """Парсинг WebSocket frame — возвращает (opcode, payload)."""
    if len(data) < 2:
        return None, b""
    b1, b2 = data[0], data[1]
    opcode = b1 & 0x0F
    masked = (b2 & 0x80) != 0
    length = b2 & 0x7F
    offset = 2
    if length == 126:
        length = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2
    elif length == 127:
        length = struct.unpack("!Q", data[offset:offset+8])[0]
        offset += 8
    if masked:
        offset += 4  # mask key
    return opcode, data[offset:offset+length]


class WebsocketMasquerade:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        u = urlparse(target)
        origin = f"{u.scheme}://{u.netloc}"
        host = u.hostname or ""
        is_tls = u.scheme == "https"
        port = u.port or (443 if is_tls else 80)

        # протокол из --extra
        ws_proto = "chat"
        for x in getattr(session, "extra", []) or []:
            if x.startswith("ws_proto="):
                ws_proto = x[9:].strip()

        protocols = WS_PROTOCOLS.get(ws_proto, WS_PROTOCOLS["chat"])

        print(f"[websocket_masquerade v2] target: {target}")
        print(f"[websocket_masquerade v2] origin: {origin}")
        print(f"[websocket_masquerade v2] protocols: {protocols}")

        findings = []
        results = []

        # === 1. Проверка через HttpClient (не через socket) — быстрый probe ===
        for path in WS_PATHS[:5]:
            url = origin + path
            ws_key = _make_ws_key()
            headers = {
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Key": ws_key,
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Protocol": ", ".join(protocols),
                "Origin": origin,
                "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
            }
            try:
                r = http.get(url, headers=headers)
            except Exception:
                continue
            if not r:
                continue

            upgraded = (r.status_code == 101 or
                        (r.headers.get("Upgrade", "").lower() == "websocket"))
            results.append({
                "path": path,
                "status": r.status_code,
                "upgraded": upgraded,
                "server_upgrade": r.headers.get("Upgrade", ""),
                "server_protocol": r.headers.get("Sec-WebSocket-Protocol", ""),
            })
            marker = "  ✓ 101" if upgraded else f"  {r.status_code}"
            print(f"{marker}  {path}")

            if upgraded:
                findings.append({
                    "type": "ws_upgrade_accepted",
                    "severity": "info",
                    "path": path,
                    "server_protocol": r.headers.get("Sec-WebSocket-Protocol", ""),
                })
                logger.finding("ws_upgrade", "info",
                               f"101 Switching Protocols at {path}")

        # === 2. Реальный socket handshake + frame test ===
        if any(r["upgraded"] for r in results):
            print()
            print(f"[websocket_masquerade v2] real socket test with frames")
            for res in results:
                if not res["upgraded"]:
                    continue
                path = res["path"]
                ok = self._socket_handshake(host, port, path, origin, is_tls,
                                            protocols, findings, logger)
                if ok:
                    print(f"  ✓ full handshake + frames OK at {path}")
                    break

        print()
        print(f"[websocket_masquerade v2] upgraded: {sum(1 for r in results if r['upgraded'])}/{len(results)}")
        print(f"[websocket_masquerade v2] findings: {len(findings)}")

        return {
            "findings": findings,
            "results": results,
        }

    def _socket_handshake(self, host, port, path, origin, is_tls,
                          protocols, findings, logger):
        """Raw socket WS handshake + frame."""
        try:
            if is_tls:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((host, port), timeout=8)
                sock = ctx.wrap_socket(sock, server_hostname=host)
            else:
                sock = socket.create_connection((host, port), timeout=8)

            ws_key = _make_ws_key()
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"Sec-WebSocket-Protocol: {', '.join(protocols)}\r\n"
                f"Origin: {origin}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
                f"\r\n"
            )
            sock.sendall(req.encode())

            resp = b""
            sock.settimeout(4)
            try:
                while b"\r\n\r\n" not in resp:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass

            text = resp.decode("latin1", errors="ignore")
            if "101" not in text.split("\r\n")[0]:
                sock.close()
                return False

            # отправляем ping frame
            ping = _ws_frame(b"omni-ping", opcode=9)
            sock.sendall(ping)
            time.sleep(0.3)

            # читаем ответ
            sock.settimeout(3)
            reply = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    reply += chunk
                    if len(reply) > 100:
                        break
            except socket.timeout:
                pass

            opcode, payload = _parse_ws_frame(reply) if reply else (None, b"")
            sock.close()

            if opcode is not None:
                findings.append({
                    "type": "ws_frame_exchange",
                    "severity": "info",
                    "path": path,
                    "opcode": opcode,
                    "reply_len": len(payload),
                })
                logger.finding("ws_frame", "info",
                               f"WS frame exchange at {path} opcode={opcode}")
            return True
        except Exception:
            return False
