"""kubernetes_api — probe k8s API (6443, 8080) for anonymous access"""
from core.http import HttpClient
from concurrent.futures import ThreadPoolExecutor, as_completed

PORTS = [6443, 8080, 8443, 10250, 10255, 2379, 8081]
PATHS = ["/api","/api/v1","/api/v1/namespaces","/api/v1/pods","/api/v1/secrets",
         "/healthz","/version","/metrics"]

class KubernetesApi:
    def run(self, session, logger):
        host = session.target.replace("https://","").replace("http://","").split("/")[0]
        if ":" in host: host = host.split(":")[0]
        http = HttpClient(session, logger)

        found = []
        for port in PORTS:
            for scheme in ("http","https") if port in (8080, 10255, 8081) else ("https","http"):
                for path in PATHS[:4]:
                    url = f"{scheme}://{host}:{port}{path}"
                    r = http.get(url)
                    if not r: continue
                    if r.status_code == 200 and ('"kind"' in r.text or '"apiVersion"' in r.text):
                        found.append({"url":url,"code":r.status_code})
                        print(f"  [!] k8s API: {url}")
                        logger.finding("k8s_api","critical",url)
                        # check secrets access
                        if path.endswith("/secrets") and "items" in r.text:
                            logger.finding("k8s_secrets","critical",f"anonymous secrets access: {url}")
                            print(f"      [!] SECRETS ACCESSIBLE")
                        break
                else:
                    continue
                break

        print(f"[kubernetes_api] {len(found)} open endpoints")
        return {"found": found}
