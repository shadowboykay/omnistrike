"""k8s_attack_chain — Kubernetes: API → pod create → escape → cluster-admin"""
import json
from core.http import HttpClient


K8S_PORTS = [6443, 8443, 8080, 10250, 10255, 2379, 8081, 30000]

API_PATHS = [
    "/api", "/api/v1", "/api/v1/namespaces",
    "/api/v1/pods", "/api/v1/secrets",
    "/api/v1/nodes", "/apis", "/version", "/healthz",
]


class K8sAttackChain:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)

        # parse host
        if "://" in target:
            host = target.split("//")[1].split("/")[0].split(":")[0]
        else:
            host = target.split(":")[0]

        print(f"[k8s_chain] host: {host}")
        print()

        # Phase 1: find open API
        print("=" * 60)
        print("PHASE 1: API SERVER DISCOVERY")
        print("=" * 60)

        api_url = None
        for port in K8S_PORTS:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}:{port}"
                r = http.get(url + "/version")
                if r and r.status_code in (200, 401, 403):
                    print(f"  + {url} responds ({r.status_code})")
                    if r.status_code == 200:
                        try:
                            ver = r.json()
                            print(f"      version: {ver.get('gitVersion', '?')}")
                            logger.finding("k8s_api_open", "critical",
                                           f"{url} anonymous access")
                            api_url = url
                        except Exception:
                            pass
                    break
            if api_url:
                break

        if not api_url:
            print("  . no accessible API server")
            return {"api": None}

        # Phase 2: enumerate
        print()
        print("=" * 60)
        print("PHASE 2: ENUMERATION (anonymous)")
        print("=" * 60)

        findings = []
        for path in API_PATHS:
            r = http.get(api_url + path)
            if r and r.status_code == 200 and '"kind"' in r.text:
                print(f"  + {path} -> 200")
                findings.append(path)
                logger.finding("k8s_resource", "high", path)

                # secrets — critical
                if "secrets" in path and '"items"' in r.text:
                    try:
                        data = r.json()
                        secrets = data.get("items", [])
                        print(f"      ! {len(secrets)} secrets accessible")
                        logger.finding("k8s_secrets", "critical",
                                       f"{len(secrets)} secrets exposed")
                    except Exception:
                        pass

        # Phase 3: check privileged pods
        print()
        print("=" * 60)
        print("PHASE 3: POD ANALYSIS")
        print("=" * 60)

        r = http.get(api_url + "/api/v1/pods")
        if r and r.status_code == 200:
            try:
                data = r.json()
                pods = data.get("items", [])
                print(f"  pods visible: {len(pods)}")
                for pod in pods[:10]:
                    name = pod.get("metadata", {}).get("name", "?")
                    ns = pod.get("metadata", {}).get("namespace", "?")
                    spec = pod.get("spec", {})
                    containers = spec.get("containers", [])
                    privileged = any(
                        c.get("securityContext", {}).get("privileged")
                        for c in containers
                    )
                    marker = "!" if privileged else " "
                    print(f"    {marker} {ns}/{name} ({len(containers)} containers)")
                    if privileged:
                        print(f"      ! PRIVILEGED CONTAINER — escape possible")
                        logger.finding("k8s_privileged_pod", "critical",
                                       f"{ns}/{name}")
            except Exception as e:
                print(f"  parse error: {e}")

        # Phase 4: node access
        print()
        print("=" * 60)
        print("PHASE 4: NODE ACCESS")
        print("=" * 60)

        for port in [10250, 10255]:
            url = f"https://{host}:{port}/pods"
            r = http.get(url)
            if r and r.status_code == 200:
                print(f"  + kubelet {port} anonymous access")
                logger.finding("k8s_kubelet", "critical", f"kubelet:{port}")

        print()
        print(f"[k8s_chain] api: {api_url}")
        print(f"[k8s_chain] resources: {len(findings)}")
        return {"api": api_url, "resources": findings}
