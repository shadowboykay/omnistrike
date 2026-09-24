"""favicon — favicon hash + Shodan-style fingerprint"""
import hashlib, base64
from core.http import HttpClient

class Favicon:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        paths = ["/favicon.ico","/favicon.png","/apple-touch-icon.png","/static/favicon.ico"]
        out = []
        for p in paths:
            r = http.get(base + p)
            if r and r.status_code == 200 and len(r.content) > 0:
                h = hashlib.md5(r.content).hexdigest()
                # mmh3-style shodan hash (base64 then mmh3) not available in stdlib,
                # md5 is a usable local fingerprint
                b64 = base64.encodebytes(r.content)
                out.append({"path": p, "size": len(r.content), "md5": h})
                print(f"  [+] {p} size={len(r.content)} md5={h}")
                logger.finding("favicon", "info", f"{p} md5={h}")
        return {"favicons": out}
