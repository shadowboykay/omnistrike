"""swagger — OpenAPI/Swagger spec discovery + endpoint extraction"""
import json, yaml
from core.http import HttpClient

SPEC_PATHS = ["/swagger.json","/openapi.json","/api-docs","/api/swagger.json","/v2/api-docs",
              "/v3/api-docs","/swagger/v1/swagger.json","/spec","/api/spec","/.well-known/openapi.json",
              "/docs","/redoc","/swagger-ui.html","/swagger-ui/","/api-docs.json","/docs/swagger.json"]

class Swagger:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        specs = []
        endpoints = []

        for path in SPEC_PATHS:
            r = http.get(base + path)
            if not r or r.status_code != 200: continue
            text = r.text.strip()
            data = None
            if text.startswith("{"):
                try: data = json.loads(text)
                except Exception: continue
            elif "swagger:" in text or "openapi:" in text:
                try: data = yaml.safe_load(text)
                except Exception: continue
            if not data: continue
            specs.append({"path":path,"data":data})
            print(f"  [+] spec: {path}")
            logger.finding("swagger_spec","high",path)
            # extract endpoints
            paths = data.get("paths", {})
            for p, methods in paths.items():
                for method in methods.keys():
                    if method.upper() in ("GET","POST","PUT","DELETE","PATCH"):
                        endpoints.append(f"{method.upper()} {p}")
                        print(f"      {method.upper()} {p}")
            if len(specs) >= 3: break

        print(f"[swagger] {len(specs)} specs, {len(endpoints)} endpoints")
        return {"specs": [s["path"] for s in specs], "endpoints": endpoints[:500]}
