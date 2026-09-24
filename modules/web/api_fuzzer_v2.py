"""api_fuzzer_v2 — smart API fuzzing: discover endpoints, test methods, params"""
from core.http import HttpClient
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


DISCOVERY_PATHS = [
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
    "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/graphql", "/graphiql", "/api/graphql",
    "/.well-known/openapi.json",
]

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

COMMON_API_ENDPOINTS = [
    "/api/users", "/api/user", "/api/accounts", "/api/auth",
    "/api/login", "/api/register", "/api/admin",
    "/api/config", "/api/health", "/api/status", "/api/version",
    "/api/v1/users", "/api/v2/users",
    "/api/orders", "/api/products", "/api/cart",
    "/api/logs", "/api/metrics", "/api/debug",
]


class ApiFuzzerV2:
    def run(self, session, logger):
        target = session.target
        base = target.rstrip("/")
        http = HttpClient(session, logger)

        print(f"[api_fuzzer] target: {target}")
        print()

        # 1. discovery
        print("=" * 60)
        print("1. DISCOVERY")
        print("=" * 60)

        found_specs = []
        found_endpoints = []

        for path in DISCOVERY_PATHS:
            r = http.get(base + path)
            if r and r.status_code == 200:
                ct = r.headers.get("Content-Type", "")
                if "json" in ct or "yaml" in ct or r.text.strip().startswith("{"):
                    print(f"  + {path} ({len(r.content)}b)")
                    found_specs.append({"path": path, "data": r.text[:5000]})
                    logger.finding("api_spec", "high", path)

        # 2. extract endpoints from specs
        print()
        print("=" * 60)
        print("2. EXTRACT ENDPOINTS FROM SPECS")
        print("=" * 60)

        api_endpoints = set()
        for spec in found_specs:
            try:
                data = json.loads(spec["data"])
                for path in data.get("paths", {}):
                    api_endpoints.add(path)
            except Exception:
                pass

        for ep in sorted(api_endpoints):
            print(f"  + {ep}")
            logger.finding("api_endpoint", "info", ep)

        # 3. method testing
        print()
        print("=" * 60)
        print("3. METHOD TESTING")
        print("=" * 60)

        interesting = []

        def test_method(item):
            method, url = item
            try:
                if method == "GET":
                    r = http.get(url)
                elif method == "POST":
                    r = http.post(url, data={})
                elif method == "PUT":
                    r = http._req("PUT", url, data={})
                elif method == "DELETE":
                    r = http._req("DELETE", url)
                elif method == "PATCH":
                    r = http._req("PATCH", url, data={})
                else:
                    r = http._req(method, url)
                if r:
                    return {"method": method, "url": url, "code": r.status_code,
                            "size": len(r.content)}
            except Exception:
                pass
            return None

        # combine discovered + common paths
        all_endpoints = list(api_endpoints) + COMMON_API_ENDPOINTS
        url_list = []
        for ep in all_endpoints[:30]:
            url = base + ep if ep.startswith("/") else base + "/" + ep
            for m in METHODS:
                url_list.append((m, url))

        with ThreadPoolExecutor(max_workers=15) as ex:
            futs = [ex.submit(test_method, item) for item in url_list]
            for f in as_completed(futs):
                r = f.result()
                if not r:
                    continue
                # interesting: 200 on non-GET, or 401/403, or method not allowed
                if r["code"] in (200, 201, 204):
                    if r["method"] != "GET":
                        interesting.append(r)
                        print(f"  + {r['method']:6s} {r['url']} -> {r['code']}")
                elif r["code"] in (401, 403):
                    interesting.append(r)
                    print(f"  ! {r['method']:6s} {r['url']} -> {r['code']} (auth needed)")

        print(f"\n[api_fuzzer] specs: {len(found_specs)}, "
              f"endpoints: {len(api_endpoints)}, interesting: {len(interesting)}")
        logger.finding("api_fuzzer", "info",
                       f"{len(interesting)} interesting methods")
        return {"specs": found_specs, "endpoints": list(api_endpoints),
                "interesting": interesting}
