"""http2_fingerprint — check server HTTP/2 support + TLS ALPN fingerprint"""
import socket, ssl
from urllib.parse import urlparse

class Http2Fingerprint:
    def run(self, session, logger):
        u = urlparse(session.target)
        if u.scheme != "https":
            print("[h2_fp] not https"); return {}
        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["h2","http/1.1"])
            with socket.create_connection((u.hostname, u.port or 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=u.hostname) as ssock:
                    proto = ssock.selected_alpn_protocol()
                    cipher = ssock.cipher()
                    ver = ssock.version()
                    print(f"[h2_fp] ALPN={proto} TLS={ver} cipher={cipher[0]}")
                    logger.finding("http2_alpn","info",f"ALPN={proto} TLS={ver}")
                    return {"alpn": proto, "tls": ver, "cipher": cipher[0]}
        except Exception as e:
            print(f"[h2_fp] error: {e}")
        return {}
