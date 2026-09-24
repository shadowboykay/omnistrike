# core/pipeline.py — chain modules into attack flows
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.loader import ModuleLoader
from core.session import Session
from core.logger import Logger
from core.report import Reporter
from core.http import HttpClient


CHAIN_RECON  = ["crt_sh","subdomain_brute","dns","dns_zone_transfer","waf_detect",
                "tech_fingerprint","cms_detect","robots","sitemap","wayback","dorks",
                "email_harvest","favicon"]
CHAIN_WEB    = ["cors","cors_advanced","csp","cookie","backup","api_leak","jwt",
                "open_redirect","http_404","swagger","graphql_attack","spring_actuator",
                "xss","sqli","lfi","ssti","ssrf","xxe","rfi","crlf","nosql_injection",
                "hpp","idor","mass_assignment","prototype_pollution","cms_detect"]
CHAIN_BYPASS = ["waf_evasion","rate_limit","403_bypass","host_header","cache_poison",
                "smuggling","h2c_smuggling","encoding"]
CHAIN_EVASION= ["googlebot_spoof","header_full_spoof","ua_rotate","referer_chain",
                "header_spoof","http_method_override"]
CHAIN_CLOUD  = ["s3_bucket","azure_blob","gcp_storage","cloudflare_origin"]
CHAIN_OSINT  = ["domain","ip","asn_lookup","email","username"]
CHAIN_MOBILE = ["apk_analyze"]

CHAIN_FULL   = CHAIN_RECON + CHAIN_WEB + CHAIN_BYPASS
CHAIN_EXTEND = CHAIN_RECON + CHAIN_WEB + CHAIN_BYPASS + CHAIN_EVASION + CHAIN_CLOUD + CHAIN_OSINT


CHAINS = {
    "recon":   [("recon", m) for m in CHAIN_RECON],
    "web":     [("web", m) for m in CHAIN_WEB],
    "bypass":  [("bypass", m) for m in CHAIN_BYPASS],
    "evasion": [("evasion", m) for m in CHAIN_EVASION],
    "cloud":   [("cloud", m) for m in CHAIN_CLOUD],
    "osint":   [("osint", m) for m in CHAIN_OSINT],
    "full":    [("recon", m) for m in CHAIN_RECON] + [("web", m) for m in CHAIN_WEB] + [("bypass", m) for m in CHAIN_BYPASS],
    "extended":[("recon", m) for m in CHAIN_RECON] + [("web", m) for m in CHAIN_WEB] +                [("bypass", m) for m in CHAIN_BYPASS] + [("evasion", m) for m in CHAIN_EVASION] +                [("cloud", m) for m in CHAIN_CLOUD] + [("osint", m) for m in CHAIN_OSINT],
}


def run_chain(name: str, target: str, proxy=None, timeout=10, threads=10):
    loader = ModuleLoader()
    session = Session(target=target, proxy=proxy, timeout=timeout, threads=threads)
    logger = Logger(session)
    print(f"[pipeline:{name}] target={target}")

    steps = CHAINS[name]
    for i, (cat, mod) in enumerate(steps, 1):
        print(f"\n[{i}/{len(steps)}] {cat}/{mod}")
        try:
            m = loader.load(cat, mod)
            if not m:
                print(f"  skip (not found)")
                continue
            m.run(session, logger)
        except Exception as e:
            logger.error("chain_step_crash", step=f"{cat}/{mod}", error=str(e))
            print(f"  error: {type(e).__name__}: {e}")

    reporter = Reporter(session, logger)
    reporter.write({"chain": name, "steps": len(steps)})
    print(f"\n[pipeline:{name}] done, findings={len(session.findings)}")
    return session
