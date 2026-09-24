"""api_hunter — pull JS files, extract API paths + websocket URLs"""
import re
from core.http import HttpClient

JS_RE = re.compile(r'(?:src|href)=["\']([^"\']+\.js[^"\']*)', re.I)
API_RE = re.compile(r'["\'](/api/[^"\']{2,80})["\']')
WS_RE = re.compile(r'(wss?://[^\s"\']+)')

class ApiHunter:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        page = http.get(base)
        if not page: return {"apis": [], "ws": []}
        js_paths = set(JS_RE.findall(page.text))
        apis, ws = set(), set()
        for js in list(js_paths)[:40]:
            u = js if js.startswith("http") else base + "/" + js.lstrip("/")
            r = http.get(u)
            if not r: continue
            for m in API_RE.findall(r.text): apis.add(m)
            for m in WS_RE.findall(r.text): ws.add(m)
        for a in sorted(apis):
            print(f"  [+] api: {a}")
            logger.finding("api_path", "low", a)
        for w in sorted(ws):
            print(f"  [+] ws: {w}")
            logger.finding("websocket", "info", w)
        print(f"[api_hunter] {len(apis)} api, {len(ws)} ws from {len(js_paths)} js")
        return {"js_count": len(js_paths), "apis": sorted(apis), "ws": sorted(ws)}
