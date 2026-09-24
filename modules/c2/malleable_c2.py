"""malleable_c2 — generate malleable C2 profile (HTTP/S parameters, jitter, headers)"""
from pathlib import Path
import json

DEFAULT_PROFILE = {
    "http-get": {
        "uri": ["/api/v1/status", "/api/v1/health", "/static/js/app.js"],
        "client": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-US,en;q=0.9",
            },
            "parameter": "id",
        },
        "server": {
            "output": {"headers": {"Server":"nginx/1.24.0","Content-Type":"text/html"}}
        }
    },
    "http-post": {
        "uri": ["/api/v1/log"],
        "client": {"parameter": "data", "headers": {"Content-Type":"application/json"}},
    },
    "sleep": 30,
    "jitter": 30,
    "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
}

class MalleableC2:
    def run(self, session, logger):
        out = Path("payloads") / "c2" / "omni_profile.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(DEFAULT_PROFILE, indent=2))
        print(f"[c2:malleable] profile written: {out}")
        print(f"  uris: {DEFAULT_PROFILE['http-get']['uri']}")
        print(f"  sleep={DEFAULT_PROFILE['sleep']}s jitter={DEFAULT_PROFILE['jitter']}%")
        logger.info("c2_profile", path=str(out))
        return {"profile": DEFAULT_PROFILE, "path": str(out)}
