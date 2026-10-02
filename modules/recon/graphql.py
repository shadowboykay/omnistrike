"""graphql v2 — GraphQL endpoint discovery with structural verification"""
from core.http import HttpClient

PATHS = ["/graphql","/api/graphql","/v1/graphql","/query","/gql","/graphiql",
         "/api/v1/graphql","/v2/graphql","/graphql/console"]


class GraphQL:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        out = []

        for p in PATHS:
            url = base + p

            # пробуем POST с introspection probe
            try:
                r = http.post(url, json={"query":"{__typename}"})
            except Exception:
                continue
            if not r:
                continue

            # 1) строгие условия: 200 + JSON
            status = r.status_code
            ct = (r.headers.get("Content-Type") or "").lower()
            if status != 200 or "json" not in ct:
                continue

            # 2) структурная проверка — parse JSON
            try:
                data = r.json()
            except Exception:
                continue
            if not isinstance(data, dict):
                continue

            is_gql = False
            d = data.get("data")
            if isinstance(d, dict) and "__typename" in d:
                is_gql = True
            errs = data.get("errors")
            if isinstance(errs, list) and errs and isinstance(errs[0], dict):
                if "locations" in errs[0] or "extensions" in errs[0]:
                    is_gql = True

            if not is_gql:
                continue

            print(f"  [+] GraphQL endpoint: {url} ({status})")
            logger.finding("graphql_endpoint", "medium", url)

            # 3) introspection
            try:
                ir = http.post(url, json={"query":"{__schema{types{name}}}"})
                if ir and ir.status_code == 200 and "__schema" in (ir.text or ""):
                    logger.finding("graphql_introspection", "medium",
                                   f"open introspection at {url}")
                    print(f"      [!] introspection enabled")
            except Exception:
                pass

            out.append({"url": url, "code": status})

        return {"endpoints": out}
