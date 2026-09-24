# core/oob_server.py — self-hosted OOB server for blind CVE detection
import socket, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime


class OOBHandler(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        OOBHandler.hits.append({
            "time": datetime.now().isoformat(),
            "path": self.path,
            "ip": self.client_address[0],
            "ua": self.headers.get("User-Agent", ""),
        })
        print(f"[OOB] HIT: {self.path} from {self.client_address[0]}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        self.do_GET()

    def log_message(self, *a):
        pass


def run(port=8888):
    print(f"[OOB] listening on 0.0.0.0:{port}")
    print(f"[OOB] use: http://<your-ip>:{port}/<unique-id>")
    try:
        HTTPServer(("0.0.0.0", port), OOBHandler).serve_forever()
    except KeyboardInterrupt:
        print(f"\n[OOB] stopped. hits: {len(OOBHandler.hits)}")
        for h in OOBHandler.hits:
            print(f"  {h['time']} {h['ip']} {h['path']}")


def get_hits():
    return list(OOBHandler.hits)


if __name__ == "__main__":
    run()
