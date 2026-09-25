#!/usr/bin/env python3
# omni_proxy.py — HTTP/HTTPS proxy with interception, edit, repeat (Burp-lite)
import socket, sys, threading, json, time, re
from datetime import datetime
from pathlib import Path
import http.server, socketserver
import urllib.request, urllib.parse

LOG_DIR = Path(__file__).parent / "proxy_logs"
LOG_DIR.mkdir(exist_ok=True)

MAX_LOG_SIZE = 50 * 1024 * 1024
MAX_LOG_AGE_DAYS = 7


def rotate_logs():
    """Remove old logs or truncate large ones."""
    import time
    now = time.time()
    for log in LOG_DIR.glob("*.jsonl"):
        try:
            if (now - log.stat().st_mtime) / 86400 > MAX_LOG_AGE_DAYS:
                log.unlink()
                print(f"[proxy] removed old: {log.name}")
                continue
            if log.stat().st_size > MAX_LOG_SIZE:
                lines = log.read_text().splitlines()
                log.write_text("\n".join(lines[-1000:]) + "\n")
                print(f"[proxy] truncated: {log.name}")
        except Exception:
            pass


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    interactive = True
    edit_enabled = False

    def log_message(self, *a): pass

    def do_GET(self):    self._proxy("GET")
    def do_POST(self):   self._proxy("POST")
    def do_PUT(self):    self._proxy("PUT")
    def do_DELETE(self): self._proxy("DELETE")
    def do_PATCH(self):  self._proxy("PATCH")
    def do_OPTIONS(self):self._proxy("OPTIONS")
    def do_HEAD(self):   self._proxy("HEAD")

    def _proxy(self, method):
        url = self.path if self.path.startswith("http") else \
              f"http://{self.headers.get('Host','')}{self.path}"

        body = None
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            body = self.rfile.read(length)

        # interactive pause
        if self.interactive and self.edit_enabled:
            self._show_request(method, url, body)
            action = input("    [P]ass/[E]dit/[D]rop/[R]epeat/[F]uzz? ").strip().lower()
            if action == "d":
                self.send_response(200); self.end_headers(); return
            elif action == "e":
                new_url = input(f"    URL [{url}]: ").strip() or url
                url = new_url
            elif action == "f":
                self._fuzz(url, method)
                self.send_response(200); self.end_headers(); return
        else:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] {method} {url[:100]}")

        self._forward(method, url, body)

    def _show_request(self, method, url, body):
        print("\n" + "=" * 60)
        print(f"INTERCEPT: {method} {url}")
        for k, v in self.headers.items():
            if k.lower() not in ("proxy-connection",):
                print(f"  {k}: {v[:80]}")
        if body:
            print(f"  body: {body[:200]}")

    def _forward(self, method, url, body):
        try:
            req = urllib.request.Request(url, method=method)
            for k, v in self.headers.items():
                if k.lower() not in ("proxy-connection", "host", "content-length"):
                    req.add_header(k, v)
            if body:
                req.data = body

            with urllib.request.urlopen(req, timeout=60) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp_body)

                self._log(method, url, body, resp.status, resp_body)
        except Exception as e:
            self.send_response(502); self.end_headers()
            self.wfile.write(f"Proxy error: {e}".encode())

    def _log(self, method, url, req_body, code, resp_body):
        log_file = LOG_DIR / f"{datetime.now().strftime('%Y%m%d')}.jsonl"
        with log_file.open("a") as f:
            f.write(json.dumps({
                "ts": datetime.now().isoformat(),
                "method": method, "url": url,
                "req_headers": dict(self.headers),
                "req_body": req_body.decode("utf-8", errors="ignore")[:2000] if req_body else "",
                "resp_code": code,
                "resp_body": resp_body.decode("utf-8", errors="ignore")[:2000],
            }) + "\n")

    def _fuzz(self, url, method):
        """Send payload mutations."""
        sys.path.insert(0, str(Path(__file__).parent))
        from core.mutator import mutate_param
        payload = input("    Payload: ").strip()
        if not payload: return
        variants = mutate_param(payload, n=5)
        print(f"    testing {len(variants)} variants...")
        for v in variants:
            test_url = url.replace(payload, v) if payload in url else url + "?" + v
            try:
                r = urllib.request.urlopen(test_url, timeout=10)
                print(f"      {r.status} -> {v[:50]}")
            except Exception as e:
                print(f"      ERR -> {v[:50]} ({e})")


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def run(port=8080, interactive=False, edit=False):
    rotate_logs()
    ProxyHandler.interactive = interactive
    ProxyHandler.edit_enabled = edit

    print(f"[proxy] listening on http://127.0.0.1:{port}")
    print(f"[proxy] logs: {LOG_DIR}")
    print(f"[proxy] mode: {'INTERACTIVE' if interactive and edit else 'passive'}")
    print()
    print("[proxy] настрой:")
    print(f"  export http_proxy=http://127.0.0.1:{port}")
    print(f"  export https_proxy=http://127.0.0.1:{port}")
    print()
    print("[proxy] для интерактива: python omni_proxy.py --edit")
    print()

    try:
        ThreadedHTTPServer(("127.0.0.1", port), ProxyHandler).serve_forever()
    except KeyboardInterrupt:
        print("\n[proxy] stopped")
        # print stats
        today = LOG_DIR / f"{datetime.now().strftime('%Y%m%d')}.jsonl"
        if today.is_file():
            n = len(today.read_text().strip().splitlines())
            print(f"[proxy] {n} requests logged today")


if __name__ == "__main__":
    port = 8080
    interactive = False
    edit = False
    for i, a in enumerate(sys.argv):
        if a == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
        elif a == "--edit":
            interactive = True
            edit = True
    run(port, interactive, edit)
