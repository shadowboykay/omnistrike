"""graphql_batch — GraphQL batching attack + depth/alias DoS detection"""
from core.http import HttpClient

ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql", "/api/v1/graphql"]

class GraphqlBatch:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        findings = []

        for ep in ENDPOINTS:
            url = base + ep
            # baseline
            r = http.post(url, json={"query": "{__typename}"})
            if not r or r.status_code not in (200, 400): continue
            print(f"[graphql_batch] {ep} ({r.status_code})")

            # 1. batching via array
            batch = [{"query": "{__typename}"}] * 50
            r2 = http.post(url, json=batch)
            if r2 and r2.status_code == 200:
                try:
                    data = r2.json()
                    if isinstance(data, list) and len(data) >= 10:
                        print(f"  [!] batching accepted: {len(data)} responses")
                        findings.append({"endpoint": ep, "type": "array_batch",
                                         "count": len(data), "severity": "medium"})
                        logger.finding("graphql_batch_array", "medium",
                                       f"{ep} {len(data)} responses")
                except Exception:
                    pass

            # 2. alias-based DoS (multiple aliases in single query)
            aliases = " ".join(f"a{i}:__typename" for i in range(100))
            r3 = http.post(url, json={"query": "{" + aliases + "}"})
            if r3 and r3.status_code == 200:
                try:
                    data = r3.json()
                    if data.get("data") and len(data["data"]) >= 50:
                        print(f"  [!] alias DoS possible: {len(data['data'])} aliases")
                        findings.append({"endpoint": ep, "type": "alias_dos",
                                         "count": len(data["data"]), "severity": "medium"})
                        logger.finding("graphql_alias_dos", "medium",
                                       f"{ep} {len(data['data'])} aliases")
                except Exception:
                    pass

            # 3. depth bomb
            deep = "{" + "{a:" * 20 + "__typename" + "}" * 20 + "}"
            r4 = http.post(url, json={"query": deep})
            if r4 and r4.status_code == 200:
                print(f"  · depth probe: {r4.status_code}")

        print(f"[graphql_batch] total: {len(findings)}")
        return {"findings": findings}
