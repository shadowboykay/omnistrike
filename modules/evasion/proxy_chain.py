"""proxy_chain — test proxy rotation (list of proxies → random pick per request)"""
import random, os
from core.http import HttpClient
from core.session import Session

class ProxyChain:
    def run(self, session, logger):
        # proxies from --extra proxy=http://... or PROXIES env (comma-separated)
        proxies = []
        for x in session.extra:
            if x.startswith("proxy="):
                proxies.append(x.split("=",1)[1])
        env_proxies = os.environ.get("PROXIES","")
        if env_proxies:
            proxies.extend([p.strip() for p in env_proxies.split(",") if p.strip()])
        if not proxies:
            print("[proxy_chain] provide proxies via --extra proxy=... or PROXIES env")
            return {}

        print(f"[proxy_chain] {len(proxies)} proxies")
        results = {}
        for i in range(min(10, len(proxies))):
            p = random.choice(proxies)
            sub_session = Session(target=session.target, proxy=p, timeout=session.timeout)
            sub_http = HttpClient(sub_session, logger)
            r = sub_http.get(session.target)
            code = r.status_code if r else None
            ip = "?"
            if r:
                # check what IP the target sees (via ipify through proxy)
                r2 = sub_http.get("https://api.ipify.org?format=json")
                if r2:
                    try: ip = r2.json().get("ip","?")
                    except Exception: pass
            print(f"  {p} -> {code} (exit ip {ip})")
            results[p] = {"code":code,"exit_ip":ip}
        return {"results": results}
