"""api_hunter v2 — API endpoint mining from HTML/JS + swagger/graphql + verify.

Источники:
  1. HTML: <script src>, <link href>, инлайн-пути /api/ /v1/ /v2/ /rest/
  2. JS файлы (до 60): fetch(, axios., XMLHttpRequest, baseURL, API_URL,
     endpoint, apiUrl, /api/, /vN/, /graphql, /rpc, /soap
  3. Swagger/OpenAPI: /swagger.json, /swagger/v1/swagger.json,
     /openapi.json, /api-docs, /v2/api-docs, /v3/api-docs, /docs, /redoc
  4. GraphQL: /graphql, /graphiql, /api/graphql, /v1/graphql
  5. WebSocket: wss://, ws:// (из HTML/JS)
  6. .well-known/: /openid-configuration, /jwks.json

Классификация:
  - REST: /api/, /vN/, /rest/, /json/
  - GraphQL: /graphql, /gql
  - WebSocket: ws://, wss://
  - RPC: /rpc, /jsonrpc
  - SOAP: /soap, /wsdl, .asmx
  - Admin: /admin, /internal, /private, /debug

Verify:
  - Каждый endpoint → GET (или HEAD) → живой? auth?
  - 200 = открытый (finding medium/high)
  - 401/403 = защищённый (info — endpoint существует)
  - 404 = мёртвый (пропускаем)
"""
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http import HttpClient


# === регексы ===
RE_JS_LINK = re.compile(r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)
RE_PATH_STR = re.compile(r'["\'](/(?:api|v\d+|rest|graphql|gql|rpc|jsonrpc|soap|wsdl|internal|admin|private|debug|swagger|openapi|docs|redoc)[^"\']{0,100})["\']')
RE_FETCH = re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open)\s*\(\s*["\']([^"\']{2,120})["\']', re.I)
RE_BASE_URL = re.compile(r'(?:baseURL|baseUrl|API_URL|apiUrl|api_url|API_BASE|apiBase|endpoint|ENDPOINT)\s*[:=]\s*["\']([^"\']{2,150})["\']', re.I)
RE_WS = re.compile(r'(wss?://[^\s"\'<]{4,150})')
RE_ABSOLUTE_HTTP = re.compile(r'(https?://[^\s"\'<]{4,150})')

# swagger/openapi/docs endpoints для прямого probe
SWAGGER_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs",
    "/v3/api-docs", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/swagger-ui.html", "/swagger-ui/", "/swagger/index.html",
    "/swagger/", "/swagger", "/redoc", "/docs", "/api/docs",
    "/spec", "/openapi.yaml", "/swagger.yaml",
    "/api/swagger.json", "/api/openapi.json",
]

# graphql endpoints
GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/v2/graphql", "/gql", "/query", "/api/v1/graphql",
]

# well-known
WELLKNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/.well-known/security.txt",
    "/.well-known/change-password",
]

# admin/sensitive
SENSITIVE_PATH_KEYS = [
    "/admin", "/internal", "/private", "/debug", "/actuator",
    "/console", "/manager", "/system", "/env", "/metrics",
    "/health", "/status", "/test", "/dev",
]


def _classify(path):
    p = path.lower()
    if "/graphql" in p or p.endswith("/gql"):
        return "graphql"
    if p.startswith("ws://") or p.startswith("wss://"):
        return "websocket"
    if "/rpc" in p or "/jsonrpc" in p:
        return "rpc"
    if "/soap" in p or "/wsdl" in p or p.endswith(".asmx"):
        return "soap"
    if "/swagger" in p or "/openapi" in p or "/docs" in p or "/redoc" in p or "/api-docs" in p:
        return "docs"
    for k in SENSITIVE_PATH_KEYS:
        if k in p:
            return "sensitive"
    if "/api/" in p or re.match(r"^/vN/", p) or "/rest/" in p:
        return "rest"
    return "other"


def _is_static(url):
    low = url.lower()
    for ext in (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                ".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif",
                ".mp4", ".mp3", ".pdf"):
        if ext in low:
            return True
    return False


def _is_noise_domain(url, target_host):
    """Отсеиваем CDN/аналитику/соцсети."""
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return True
    noise = ["google-analytics", "googletagmanager", "doubleclick",
             "facebook.com", "twitter.com", "linkedin.com",
             "cdn.jsdelivr", "unpkg.com", "cdnjs", "bootstrapcdn",
             "cloudflare.com", "fontawesome", "gstatic",
             "wixpress.com", "sentry.io", "sentry-cdn"]
    for n in noise:
        if n in host:
            return True
    # same-origin или internal — ok
    if not host or host == target_host or host.endswith("." + target_host):
        return False
    # внешние URL — оставляем (могут быть API)
    return False


class ApiHunter:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        u = urlparse(base)
        origin = u.scheme + "://" + u.netloc if u.scheme else base
        target_host = u.hostname or ""
        http = HttpClient(session, logger)

        print("[api_hunter v2] target: " + base)

        # === 1. main page + JS collection ===
        try:
            page = http.get(base)
        except Exception:
            page = None

        if not page:
            print("[api_hunter v2] main page unreachable")
            return {"apis": [], "ws": [], "js_count": 0}

        html = page.text or ""
        js_paths = set(RE_JS_LINK.findall(html))
        print("[api_hunter v2] js files found in HTML: " + str(len(js_paths)))

        apis = set()
        ws_urls = set()

        # paths из главной
        for m in RE_PATH_STR.findall(html):
            apis.add(m)
        for m in RE_FETCH.findall(html):
            if not _is_static(m):
                apis.add(m)
        for m in RE_BASE_URL.findall(html):
            apis.add(m)
        for m in RE_WS.findall(html):
            ws_urls.add(m)

        # === 2. JS scan (up to 60) ===
        js_list = list(js_paths)[:60]
        def scan_js(js):
            u_js = urljoin(origin + "/", js) if not js.startswith("http") else js
            if _is_noise_domain(u_js, target_host):
                return set(), set()
            try:
                r = http.get(u_js)
            except Exception:
                return set(), set()
            if not r or r.status_code != 200:
                return set(), set()
            t = r.text or ""
            found = set()
            for m in RE_PATH_STR.findall(t):
                found.add(m)
            for m in RE_FETCH.findall(t):
                if not _is_static(m):
                    found.add(m)
            for m in RE_BASE_URL.findall(t):
                found.add(m)
            w = set(RE_WS.findall(t))
            return found, w

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(scan_js, js) for js in js_list]
            for f in as_completed(futs):
                try:
                    found, w = f.result()
                    apis |= found
                    ws_urls |= w
                except Exception:
                    pass

        print("[api_hunter v2] raw paths from JS/HTML: " + str(len(apis)))

        # === 3. прямые probe swagger/graphql/wellknown ===
        print()
        print("[api_hunter v2] probing swagger/graphql/well-known")

        def probe(path):
            try:
                r = http.get(origin + path, allow_redirects=False)
            except Exception:
                return None
            if not r:
                return None
            return {"path": path, "status": r.status_code, "size": len(r.content or b"")}

        probe_paths = SWAGGER_PATHS + GRAPHQL_PATHS + WELLKNOWN_PATHS
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(probe, p) for p in probe_paths]
            for f in as_completed(futs):
                try:
                    res = f.result()
                except Exception:
                    res = None
                if not res:
                    continue
                st = res["status"]
                if st in (200, 401, 403):
                    apis.add(res["path"])
                    marker = "  [auth]" if st in (401, 403) else "  [open]"
                    print("    " + res["path"] + " -> " + str(st) + marker)

        # === 4. classify + filter ===
        by_category = {}
        for a in apis:
            if _is_static(a):
                continue
            if a.startswith("http"):
                if _is_noise_domain(a, target_host):
                    continue
            cat = _classify(a)
            by_category.setdefault(cat, set()).add(a)

        # === 5. verify top live endpoints (max 15) ===
        print()
        print("[api_hunter v2] verifying live endpoints (max 15)")
        verified = []
        to_verify = []
        for cat in ("rest", "graphql", "sensitive", "docs", "rpc", "soap"):
            for a in list(by_category.get(cat, []))[:5]:
                if a.startswith("/"):
                    to_verify.append(a)

        def check_path(p):
            url = origin + p if p.startswith("/") else p
            try:
                r = http.get(url, allow_redirects=False)
            except Exception:
                return None
            if not r:
                return None
            return {"path": p, "status": r.status_code, "size": len(r.content or b"")}

        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = [ex.submit(check_path, p) for p in to_verify[:15]]
            for f in as_completed(futs):
                try:
                    res = f.result()
                except Exception:
                    res = None
                if not res:
                    continue
                st = res["status"]
                if st == 404:
                    continue
                marker = "  [open]" if st == 200 else ("  [auth]" if st in (401, 403) else "")
                print("    " + res["path"] + " -> " + str(st) + marker)
                verified.append(res)

        # === 6. output + findings ===
        print()
        print("[api_hunter v2] by category:")
        for cat, items in sorted(by_category.items()):
            print("  " + cat + ": " + str(len(items)))
            for a in list(items)[:3]:
                print("    " + a)

        try:
            logger.finding("api_hunter_summary", "info",
                           target_host + ": " + str(len(apis)) + " endpoints, " +
                           str(len(verified)) + " live, " + str(len(js_list)) + " js files")
            for cat in ("graphql", "sensitive", "rpc", "soap"):
                for a in list(by_category.get(cat, []))[:5]:
                    logger.finding("api_" + cat, "medium", a)
            for v in verified:
                sev = "info"
                if v["status"] == 200 and _classify(v["path"]) == "sensitive":
                    sev = "high"
                elif v["status"] == 200:
                    sev = "medium"
                logger.finding("api_live", sev, v["path"] + " " + str(v["status"]))
        except Exception:
            pass

        print()
        print("[api_hunter v2] total api: " + str(len(apis)) +
              ", ws: " + str(len(ws_urls)) +
              ", verified live: " + str(len(verified)))

        return {
            "js_count": len(js_paths),
            "apis": sorted(apis),
            "ws": sorted(ws_urls),
            "by_category": {k: sorted(v) for k, v in by_category.items()},
            "verified": verified,
        }
