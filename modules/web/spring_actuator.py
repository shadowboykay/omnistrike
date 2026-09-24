"""spring_actuator — Spring Boot Actuator endpoint discovery + data leak"""
import json
from core.http import HttpClient

ENDPOINTS = ["/actuator","/actuator/health","/actuator/info","/actuator/env","/actuator/beans",
             "/actuator/configprops","/actuator/mappings","/actuator/heapdump","/actuator/threaddump",
             "/actuator/loggers","/actuator/metrics","/actuator/httptrace","/actuator/auditevents",
             "/actuator/scheduledtasks","/actuator/caches","/actuator/conditions","/actuator/flyway",
             "/actuator/liquibase","/actuator/sessions","/actuator/shutdown",
             "/env","/health","/info","/beans","/mappings","/heapdump"]

class SpringActuator:
    def run(self, session, logger):
        base = session.target.rstrip("/")
        http = HttpClient(session, logger)
        found = []
        for ep in ENDPOINTS:
            r = http.get(base + ep)
            if not r or r.status_code != 200: continue
            ct = r.headers.get("Content-Type","")
            # actuator returns JSON usually
            if "json" in ct.lower() or r.text.strip().startswith("{"):
                found.append(ep)
                print(f"  [+] {ep}")
                logger.finding("spring_actuator","high",ep)
                # specific data extraction
                if ep.endswith("/env"):
                    try:
                        data = r.json()
                        for prop in data.get("propertySources", []):
                            src = prop.get("name","")
                            for k, v in prop.get("properties", {}).items():
                                val = v.get("value","")
                                if any(s in k.lower() for s in ("password","secret","key","token","credential")):
                                    print(f"      [!] {k} = {val[:60]}")
                                    logger.finding("spring_secret","critical",f"{k}={val[:60]}")
                                if src and any(s in src.lower() for s in ("password","secret","key")):
                                    logger.finding("spring_source","high",f"{src} = {val[:60]}")
                    except Exception: pass
                elif ep.endswith("/heapdump") and len(r.content) > 100000:
                    logger.finding("heapdump","critical",f"heapdump downloadable, {len(r.content)} bytes")
                    print(f"      [!] heapdump {len(r.content)} bytes — can contain passwords")
                elif ep.endswith("/mappings"):
                    logger.finding("mappings_leak","medium","all routes exposed")
        if not found:
            print("[spring_actuator] no endpoints")
        return {"endpoints": found}
