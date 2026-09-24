"""graphql — GraphQL endpoint discovery + introspection query"""
from core.http import HttpClient

PATHS = ["/graphql","/api/graphql","/v1/graphql","/query","/gql","/graphiql","/api/v1/graphql"]
INTROSPECT = '{"query":"{__schema{types{name kind}}}"}'

class GraphQL:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        out = []
        for p in PATHS:
            url = base + p
            r = http.get(url)
            if r and r.status_code in (200, 400, 405):
                print(f"  [+] {url} ({r.status_code})")
                logger.finding("graphql_endpoint", "low", url)
                pr = http.post(url, json={"query":"{__typename}"})
                if pr and "data" in pr.text.lower():
                    print(f"      introspection likely enabled")
                    ir = http.post(url, json={"query":"{__schema{types{name}}}"})
                    if ir and "__schema" in ir.text:
                        logger.finding("graphql_introspection", "medium", f"open introspection at {url}")
                        print(f"      [!] INTROSPECTION OPEN")
                out.append({"url": url, "code": r.status_code})
        return {"endpoints": out}
