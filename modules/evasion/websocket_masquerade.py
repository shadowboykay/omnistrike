"""websocket_masquerade — tunnel HTTP through WebSocket-like upgrades"""
from core.http import HttpClient
import base64, os

class WebsocketMasquerade:
    def run(self, session, logger):
        http = HttpClient(session, logger)
        # send request with websocket upgrade headers to look like WS handshake
        ws_key = base64.b64encode(os.urandom(16)).decode()
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": ws_key,
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Protocol": "graphql-ws, chat, mqtt",
        }
        r = http.get(session.target, headers=headers)
        if r:
            print(f"[ws_masq] {r.status_code} (upgrade {r.headers.get('Upgrade','none')})")
            if r.status_code == 101:
                logger.finding("ws_upgrade","info","server accepts WS upgrade")
        return {"code": r.status_code if r else None}
