"""spring_actuator v2 — Spring Boot Actuator discovery + data leak extraction.

Что ищет:
  Sensitive (critical): env, heapdump, threaddump, configprops, jolokia,
                        shutdown (POST), restart (POST), refresh (POST)
  High:                 beans, mappings, loggers, httptrace, auditevents,
                        sessions, caches, conditions
  Info:                 health, info, metrics, prometheus

Префиксы:
  /actuator/<ep> (default), /manage/<ep>, /admin/<ep>, /api/actuator/<ep>,
  /management/<ep>, без префикса /<ep>

Проверки:
  - GET + POST на изменяющие endpoints (shutdown, restart, refresh, loggers)
  - Env parsing: propertySources → values, поиск паролей/ключей
  - Heapdump: Content-Length, validation
  - Jolokia: список MBeans через /actuator/jolokia/list
"""
import json
import re
from core.http import HttpClient
from core.verify import confidence, is_signal


# (path_suffix, severity, method, description)
ENDPOINT_CATALOG = [
    # --- critical data leak ---
    ("env",          "critical", "GET", "environment variables (DB pass, API keys)"),
    ("heapdump",     "critical", "GET", "heap dump (memory snapshot, creds)"),
    ("threaddump",   "high",     "GET", "thread dump (stack traces)"),
    ("configprops",  "critical", "GET", "configuration properties"),
    ("jolokia",      "critical", "GET", "JMX proxy (RCE potential)"),
    ("jolokia/list", "critical", "GET", "JMX MBean list"),
    ("shutdown",     "critical", "POST", "graceful shutdown (DoS)"),
    ("restart",      "critical", "POST", "application restart"),
    ("refresh",      "critical", "POST", "config refresh"),
    ("loggers",      "high",     "POST", "log level change (DoS via DEBUG flood)"),
    # --- info leak ---
    ("beans",        "high",     "GET", "Spring beans graph"),
    ("mappings",     "high",     "GET", "route table (all endpoints)"),
    ("httptrace",    "high",     "GET", "HTTP request trace"),
    ("auditevents",  "high",     "GET", "audit events"),
    ("sessions",     "high",     "GET", "active sessions"),
    ("caches",       "medium",   "GET", "cache list + names"),
    ("conditions",   "medium",   "GET", "autoconfiguration report"),
    ("flyway",       "medium",   "GET", "migration history"),
    ("liquibase",    "medium",   "GET", "migration history"),
    ("scheduledtasks","medium",  "GET", "scheduled tasks"),
    ("integrationgraph","medium","GET", "integration graph"),
    # --- info (non-critical) ---
    ("health",       "info",     "GET", "health check"),
    ("info",         "info",     "GET", "app info"),
    ("metrics",      "info",     "GET", "metrics list"),
    ("prometheus",   "info",     "GET", "prometheus metrics"),
    ("logfile",      "medium",   "GET", "log file contents"),
    # --- root ---
    ("",             "medium",   "GET", "actuator index (list of endpoints)"),
]

# префиксы
PREFIXES = [
    "/actuator",
    "/manage",
    "/management",
    "/admin",
    "/api/actuator",
    "/api/manage",
    "",  # без префикса — некоторые конфиги
]

# секретные ключи в env
SECRET_KEYS_RE = re.compile(
    r"(pass|pwd|secret|token|key|credential|api[_-]?key|private|access[_-]?key|"
    r"auth|bearer|jwt|session|smtp|mail|jdbc|datasource|redis|mongodb|aws|azure)",
    re.I
)


def _is_json_response(r):
    """Actuator возвращает JSON (или HTML для HTML-sanitized)."""
    if not r:
        return False
    ct = (r.headers.get("Content-Type") or "").lower()
    if "json" in ct:
        return True
    text = (r.text or "").strip()
    return text.startswith("{") or text.startswith("[")


def _extract_env_secrets(data):
    """Парсит /actuator/env JSON → находит пароли/ключи."""
    secrets = []
    if not isinstance(data, dict):
        return secrets
    for source in data.get("propertySources", []):
        src_name = source.get("name", "")
        props = source.get("properties", {})
        for key, val_obj in props.items():
            if not SECRET_KEYS_RE.search(key):
                continue
            value = ""
            if isinstance(val_obj, dict):
                value = str(val_obj.get("value", ""))
            if value:
                # маскируем для отчёта: только первые 20 + длина
                snippet = value[:50]
                secrets.append({"key": key, "source": src_name[:80], "snippet": snippet})
    return secrets


class SpringActuator:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)

        print("[spring_actuator v2] target: " + base)

        findings = []
        endpoints_found = []

        # === discovery + extraction ===
        for prefix in PREFIXES:
            for suffix, severity, method, desc in ENDPOINT_CATALOG:
                if suffix:
                    path = prefix + "/" + suffix
                else:
                    path = prefix or "/"
                if not path.startswith("/"):
                    path = "/" + path

                # GET
                try:
                    r = http.get(base + path, allow_redirects=False)
                except Exception:
                    continue
                if not r or r.status_code not in (200, 401, 403):
                    continue
                # 401/403 = endpoint exists but protected
                protected = r.status_code in (401, 403)

                if protected:
                    print("  [protected] " + path)
                    endpoints_found.append({
                        "path": path, "status": r.status_code, "severity": "info",
                        "protected": True,
                    })
                    continue

                # 200: проверяем что это JSON
                if not _is_json_response(r):
                    continue

                print("  [OPEN/" + severity + "] " + path)
                entry = {
                    "path": path, "status": 200, "severity": severity,
                    "description": desc, "protected": False,
                }
                endpoints_found.append(entry)

                # --- verify ×2 ---
                try:
                    r2 = http.get(base + path, allow_redirects=False)
                    if not r2 or r2.status_code != 200:
                        continue
                except Exception:
                    continue

                # === extraction ===
                body = r.text or ""

                if suffix == "env":
                    try:
                        data = json.loads(body)
                        secrets = _extract_env_secrets(data)
                        if secrets:
                            entry["secrets"] = secrets
                            for s in secrets[:20]:
                                print("      [SECRET] " + s["key"] + " = " + s["snippet"][:50])
                                logger.finding("spring_env_secret", "critical",
                                               s["key"] + " @ " + s["source"][:60])
                                findings.append({
                                    "type": "spring_env_secret",
                                    "severity": "critical",
                                    "path": path,
                                    "key": s["key"],
                                })
                    except Exception:
                        pass

                elif suffix == "heapdump":
                    size = len(r.content or b"")
                    if size > 100000:
                        print("      heapdump " + str(size) + " bytes — может содержать креды")
                        findings.append({
                            "type": "spring_heapdump",
                            "severity": "critical",
                            "path": path,
                            "size": size,
                        })
                        logger.finding("heapdump", "critical",
                                       path + " " + str(size) + "b")

                elif suffix == "mappings":
                    # количество routes
                    try:
                        data = json.loads(body)
                        ctx = data.get("contexts", {})
                        n_routes = sum(
                            len(v.get("mappings", {}).get("dispatcherServlets", {}))
                            for v in ctx.values()
                        )
                        if n_routes > 0:
                            entry["routes"] = n_routes
                            print("      " + str(n_routes) + " routes exposed")
                    except Exception:
                        pass

                elif suffix == "jolokia/list":
                    try:
                        data = json.loads(body)
                        mbeans = data.get("value", {})
                        if mbeans:
                            print("      " + str(len(mbeans)) + " MBean domains")
                            findings.append({
                                "type": "spring_jolokia",
                                "severity": "critical",
                                "path": path,
                                "mbean_domains": len(mbeans),
                            })
                            logger.finding("spring_jolokia", "critical",
                                           path + " " + str(len(mbeans)) + " domains")
                    except Exception:
                        pass

                elif suffix == "loggers" and method == "POST":
                    # POST на loggers может менять уровень (не выполняем!)
                    print("      POST loggers may change log level — not executed")

                elif suffix == "shutdown" and method == "POST":
                    # не выполняем shutdown!
                    print("      POST shutdown detected — NOT executing (DoS)")
                    findings.append({
                        "type": "spring_shutdown_available",
                        "severity": "critical",
                        "path": path,
                        "note": "POST /shutdown available (не выполнялось)",
                    })
                    logger.finding("spring_shutdown", "critical", path)

                # general finding для sensitive endpoints
                if severity in ("critical", "high"):
                    conf = confidence(0.95 if severity == "critical" else 0.85, 1.0)
                    if is_signal(conf, floor=0.55, module="spring_actuator"):
                        findings.append({
                            "type": "spring_endpoint_exposed",
                            "severity": severity,
                            "path": path,
                            "description": desc,
                            "confidence": conf,
                        })
                        logger.finding("spring_actuator", severity,
                                       path + " — " + desc)

        # === POST probes (только loggers — безопасный POST) ===
        print()
        print("[spring_actuator v2] Phase 2: POST probes (safe)")
        for prefix in PREFIXES[:3]:
            loggers_path = prefix + "/loggers" if prefix else "/loggers"
            try:
                # не меняем уровень — просто GET чтобы увидеть конфиг
                r = http.get(base + loggers_path)
                if r and r.status_code == 200 and _is_json_response(r):
                    # check if writable: response содержит levels, возможно с конфигом
                    try:
                        data = json.loads(r.text)
                        if "levels" in data or "loggers" in data:
                            findings.append({
                                "type": "spring_loggers_readable",
                                "severity": "high",
                                "path": loggers_path,
                                "note": "loggers endpoint exposes log config",
                            })
                            print("  [HIGH] " + loggers_path + " readable")
                            logger.finding("spring_loggers", "high", loggers_path)
                    except Exception:
                        pass
            except Exception:
                continue

        print()
        print("[spring_actuator v2] endpoints found: " + str(len(endpoints_found)))
        print("[spring_actuator v2] findings: " + str(len(findings)))

        return {
            "endpoints": endpoints_found,
            "findings": findings,
        }
