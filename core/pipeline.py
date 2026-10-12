# core/pipeline.py — chain modules into attack flows
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.loader import ModuleLoader
from core.session import Session
from core.logger import Logger
from core.report import Reporter


# ============ recon chain ============
CHAIN_RECON = [
    # core discovery
    "crt_sh", "subdomain_brute", "dns", "dns_zone_transfer",
    "dns_history", "urlscan", "asn_lookup",
    # fingerprint
    "waf_detect", "tech_fingerprint", "favicon", "shodan_query",
    # content
    "robots", "sitemap", "wayback", "email_harvest",
    # api
    "api_hunter", "graphql", "params", "swagger",
    # buckets
    "s3_bucket",
    # compliance
    "compliance_check",
]

# ============ web chain (50 modules) ============
CHAIN_WEB = [
    # discovery
    "cors", "cors_advanced", "csp", "cookie", "backup", "api_leak",
    "swagger", "graphql_attack", "graphql_batch", "spring_actuator",
    "cms_detect", "wpscan_lite",
    # logic
    "http_404", "open_redirect", "idor", "mass_assignment", "race_condition",
    "hpp", "http_method_override", "cache_deception",
    "ssi_injection", "websocket", "websocket_fuzz",
    # auth
    "jwt", "jwt_bypass", "jwt_confusion", "saml_attack", "oauth_misconfig",
    "oauth_token_theft", "session_hijack", "password_reset_flaws",
    "file_upload_bypass",
    # injection
    "crlf", "http_request_splitting", "nosql_injection", "ldap_injection",
    "xss", "xss_dom", "sqli", "lfi", "ssti", "ssrf", "rfi", "xxe",
    "csti_injection", "xslt_injection",
    # advanced
    "smuggling_advanced", "h2c_smuggling", "host_header_advanced",
    "csv_injection", "email_header_injection", "deserialization_advanced",
]

# ============ bypass chain ============
CHAIN_BYPASS = [
    "waf_evasion", "rate_limit", "403_bypass", "host_header",
    "cache_poison", "smuggling", "encoding",
]

# ============ evasion chain ============
CHAIN_EVASION = [
    "googlebot_spoof", "header_full_spoof", "ua_rotate", "referer_chain",
    "header_spoof", "dns_over_https", "request_timing", "delay_jitter",
]

# ============ cloud chain ============
CHAIN_CLOUD = ["azure_blob", "gcp_storage", "cloudflare_origin", "kubernetes_api"]

# ============ osint chain ============
CHAIN_OSINT = ["domain", "ip", "email", "username"]

# ============ dump chain ============
CHAIN_DUMP = ["api_dump", "sqli_dump", "lfi_dump", "ssrf_dump", "xxe_dump", "rce_dump"]


# ============ exploit chain (CVE-specific) ============
CHAIN_EXPLOIT = [
    # fingerprint-based (generic)
    "cve_match", "cve_scan", "default_creds",
    # popular CVEs 2021-2025
    "log4shell", "spring4shell", "shellshock",
    "citrix_adc", "citrix_bleed",
    "confluence_ognl", "exchange_proxyshell",
    "moveit_sqli", "ivanti_csa", "ivanti_epmm",
    "fortinet_sslvpn", "cisco_iosxe", "nextjs_rce",
    "panos_rce", "teamcity_auth", "php_cgi",
    "jenkins_rce",
    # generic vuln classes
    "prototype_pollution", "subdomain_takeover",
]


# ============ post chain ============
CHAIN_POST = [
    "privesc_check", "persistence", "lateral",
    "attack_graph", "defense_analyzer",
    "cleanup", "diff_scan", "loot",
]


# ============ ad chain ============
CHAIN_AD = ["ldap_enum", "checklist"]


# ============ mobile chain ============
CHAIN_MOBILE = ["apk_analyze", "dex_decompile", "frida_hook", "ios_plist"]


# ============ c2 chain ============
CHAIN_C2 = ["agent_builder", "beacon_dns", "listener"]

# ============ compose ============
CHAINS = {
    "recon":    [("recon", m) for m in CHAIN_RECON],
    "web":      [("web", m) for m in CHAIN_WEB],
    "bypass":   [("bypass", m) for m in CHAIN_BYPASS],
    "evasion":  [("evasion", m) for m in CHAIN_EVASION],
    "cloud":    [("cloud", m) for m in CHAIN_CLOUD],
    "osint":    [("osint", m) for m in CHAIN_OSINT],
    "dump":     [("dump", m) for m in CHAIN_DUMP],
    "exploit":  [("exploit", m) for m in CHAIN_EXPLOIT],
    "post":     [("post", m) for m in CHAIN_POST],
    "ad":       [("ad", m) for m in CHAIN_AD],
    "mobile":   [("mobile", m) for m in CHAIN_MOBILE],
    "c2":       [("c2", m) for m in CHAIN_C2],

    # compositions
    "full":     [("recon", m) for m in CHAIN_RECON] +
                [("web", m) for m in CHAIN_WEB] +
                [("bypass", m) for m in CHAIN_BYPASS] +
                [("exploit", m) for m in CHAIN_EXPLOIT] +
                [("dump", m) for m in CHAIN_DUMP],

    "extended": [("recon", m) for m in CHAIN_RECON] +
                [("web", m) for m in CHAIN_WEB] +
                [("bypass", m) for m in CHAIN_BYPASS] +
                [("exploit", m) for m in CHAIN_EXPLOIT] +
                [("dump", m) for m in CHAIN_DUMP] +
                [("evasion", m) for m in CHAIN_EVASION] +
                [("cloud", m) for m in CHAIN_CLOUD] +
                [("osint", m) for m in CHAIN_OSINT] +
                [("post", m) for m in CHAIN_POST],

    "auto":     None,  # special: auto_exploit chain with chaining (see below)
}


def run_chain(name, target, proxy=None, timeout=10, threads=10):
    loader = ModuleLoader()
    session = Session(target=target, proxy=proxy, timeout=timeout, threads=threads)
    logger = Logger(session)
    print(f"[pipeline:{name}] target={target}")

    if name == "auto":
        from core.auto_exploit import run_auto_exploit
        run_auto_exploit(session, logger, loader)
    else:
        steps = CHAINS[name]
        for i, (cat, mod) in enumerate(steps, 1):
            print(f"\n[{i}/{len(steps)}] {cat}/{mod}")
            try:
                m = loader.load(cat, mod)
                if not m:
                    print(f"  skip (not found)")
                    continue
                m.run(session, logger)
            except KeyboardInterrupt:
                print("\n[!] interrupted")
                break
            except Exception as e:
                logger.error("chain_step_crash", step=f"{cat}/{mod}", error=str(e))
                print(f"  error: {type(e).__name__}: {e}")

    reporter = Reporter(session, logger)
    reporter.write({"chain": name})
    print(f"\n[pipeline:{name}] done, findings={len(session.findings)}")
    return session
