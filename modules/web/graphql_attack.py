"""graphql_attack — GraphQL introspection + mutation/query fuzzing"""
from core.http import HttpClient

INTROSPECT = '{"query":"{__schema{queryType{name} mutationType{name} subscriptionType{name} types{name kind fields{name type{name kind ofType{name kind}}}}}}"}'

ENDPOINTS = ["/graphql","/api/graphql","/v1/graphql","/query","/gql","/graphiql","/graphql/console"]

class GraphQLAttack:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        info = {"endpoints": [], "types": [], "mutations": [], "queries": []}

        for ep in ENDPOINTS:
            url = base + ep
            r = http.post(url, json={"query":"{__typename}"})
            if not r or r.status_code not in (200, 400): continue
            info["endpoints"].append(ep)
            print(f"  [+] {ep}")
            logger.finding("graphql_endpoint","medium",ep)

            # introspection
            r2 = http.post(url, json={"query":INTROSPECT.replace('{"query":"','').rstrip('"}')})
            # actually send as proper json
            r2 = http.post(url, json={"query":"{__schema{types{name kind}}}"})
            if r2 and "__schema" in r2.text:
                print(f"      [!] INTROSPECTION ENABLED")
                logger.finding("graphql_introspection","high",ep)
                try:
                    data = r2.json()
                    types = [t["name"] for t in data.get("data",{}).get("__schema",{}).get("types",[])]
                    info["types"] = [t for t in types if not t.startswith("__")]
                    print(f"      types: {len(info['types'])}")
                except Exception: pass

            # query/mutation names
            r3 = http.post(url, json={"query":"{__type(name:\"Query\"){fields{name}}}"})
            if r3 and r3.status_code == 200:
                try:
                    data = r3.json()
                    for f in data.get("data",{}).get("__type",{}).get("fields",[]) or []:
                        info["queries"].append(f["name"])
                except Exception: pass
            r4 = http.post(url, json={"query":"{__type(name:\"Mutation\"){fields{name}}}"})
            if r4 and r4.status_code == 200:
                try:
                    data = r4.json()
                    for f in data.get("data",{}).get("__type",{}).get("fields",[]) or []:
                        info["mutations"].append(f["name"])
                except Exception: pass

        print(f"[graphql_attack] {len(info['endpoints'])} endpoints, {len(info['queries'])} queries, {len(info['mutations'])} mutations")
        return info
