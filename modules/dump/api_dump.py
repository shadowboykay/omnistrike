"""api_dump — extract data from REST API by enumerating endpoints"""
import json
from core.http import HttpClient
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

ENDPOINTS = [
    "/api/users","/api/v1/users","/api/v2/users",
    "/api/admin","/api/v1/admin","/api/config",
    "/api/products","/api/orders","/api/customers",
    "/api/accounts","/api/transactions","/api/payments",
    "/api/logs","/api/health","/api/status","/api/version",
    "/api/users/1","/api/users/2","/api/admin/users",
]

class ApiDump:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        out_dir = Path("reports") / "dump" / "api"
        out_dir.mkdir(parents=True, exist_ok=True)
        dumped = {}

        def fetch(path):
            r = http.get(base + path)
            if not r: return None
            if r.status_code != 200: return None
            ct = r.headers.get("Content-Type","")
            if "json" not in ct.lower() and not r.text.strip().startswith(("{","[")):
                return None
            return path, r.text

        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = [ex.submit(fetch, p) for p in ENDPOINTS]
            for f in as_completed(futs):
                res = f.result()
                if not res: continue
                path, body = res
                fname = path.replace("/","_").strip("_") + ".json"
                (out_dir / fname).write_text(body[:100000])
                dumped[path] = len(body)
                print(f"  [+] {path} ({len(body)}b)")
                logger.finding("api_dump", "high", f"{path} ({len(body)} bytes)")

        print(f"[api_dump] {len(dumped)} endpoints dumped to {out_dir}")
        return {"dumped": list(dumped.keys())}
