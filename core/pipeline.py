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
    "crt_sh", "subdomain_brute", "dns", "dns_zone_transfer", "waf_detect",
    "tech_fingerprint", "cms_detect", "robots", "sitemap", "wayback", "dorks",
    "email_harvest", "favicon", "shodan_query",
]

# ============ web chain (50 modules) ============
CHAIN_WEB = [
    # discovery
    "cors", "cors_advanced", "csp", "cookie", "backup", "api_leak",
    "swagger", "graphql_attack", "graphql_batch", "spring_actuator",
    "cms_detect", "wpscan_lite",
    # logic
    "http_404", "open_redirect", "idor", "mass_assignment", "race_condition",
    "hpp", "prototype_pollution", "http_method_override", "cache_deception",
    "ssi_injection", "websocket", "websocket_fuzz",
    # auth
    "jwt", "jwt_bypass", "saml_attack", "oauth_misconfig",
    "password_reset_flaws", "file_upload_bypass",
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
    "cache_poison", "smuggling", "h2c_smuggling", "encoding",
]

# ============ evasion chain ============
CHAIN_EVASION = [
    "googlebot_spoof", "header_full_spoof", "ua_rotate", "referer_chain",
    "header_spoof", "http_method_override", "dns_over_https",
    "request_timing", "delay_jitter",
]

# ============ cloud chain ============
CHAIN_CLOUD = ["s3_bucket", "azure_blob", "gcp_storage", "cloudflare_origin", "kubernetes_api"]

# ============ osint chain ============
CHAIN_OSINT = ["domain", "ip", "asn_lookup", "email", "username", "urlscan"]

# ============ dump chain ============
CHAIN_DUMP = ["api_dump", "sqli_dump", "sqli_post_dump", "lfi_dump", "ssrf_dump", "xxe_dump", "rce_dump"]

# ============ compose ============
CHAINS = {
    "recon":    [("recon", m) for m in CHAIN_RECON],
    "web":      [("web", m) for m in CHAIN_WEB],
    "bypass":   [("bypass", m) for m in CHAIN_BYPASS],
    "evasion":  [("evasion", m) for m in CHAIN_EVASION],
    "cloud":    [("cloud", m) for m in CHAIN_CLOUD],
    "osint":    [("osint", m) for m in CHAIN_OSINT],
    "dump":     [("dump", m) for m in CHAIN_DUMP],
    "full":     [("recon", m) for m in CHAIN_RECON] +
                [("web", m) for m in CHAIN_WEB] +
                [("bypass", m) for m in CHAIN_BYPASS],
    "extended": [("recon", m) for m in CHAIN_RECON] +
                [("web", m) for m in CHAIN_WEB] +
                [("bypass", m) for m in CHAIN_BYPASS] +
                [("evasion", m) for m in CHAIN_EVASION] +
                [("cloud", m) for m in CHAIN_CLOUD] +
                [("osint", m) for m in CHAIN_OSINT],
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
