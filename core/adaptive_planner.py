# core/adaptive_planner.py — adaptive pipeline: recon → plan → attack → chain
from core.loader import ModuleLoader


# Быстрая разведка — даёт теги, не тормозит
RECON_PHASE = [
    ("recon", "waf_detect"),
    ("recon", "tech_fingerprint"),
    ("web", "cms_detect"),
    ("recon", "robots"),
]

# Медленная разведка — только с --full-recon
SLOW_RECON = [
    ("recon", "sitemap"),
    ("recon", "api_hunter"),
    ("web", "swagger"),
]


RULES = {
    "waf:cloudflare": [("evasion", "chameleon_v2"), ("evasion", "swarm_mode_v3"),
                       ("bypass", "waf_evasion")],
    "waf:akamai":     [("evasion", "chameleon_v2"), ("bypass", "waf_evasion"),
                       ("bypass", "encoding")],
    "waf:imperva":    [("bypass", "waf_evasion"), ("evasion", "header_spoof")],
    "waf:f5":         [("bypass", "403_bypass"), ("evasion", "header_spoof")],

    "cms:wordpress":  [("web", "wpscan_lite"), ("web", "backup"),
                       ("exploit", "cve_match"), ("web", "api_leak")],
    "cms:drupal":     [("exploit", "cve_match"), ("web", "backup")],
    "cms:joomla":     [("web", "backup"), ("exploit", "cve_match")],

    "tech:php":       [("web", "lfi"), ("web", "rfi"), ("web", "backup")],
    "tech:aspnet":    [("web", "http_404"), ("exploit", "cve_match")],
    "tech:spring":    [("web", "spring_actuator"), ("exploit", "spring4shell")],
    "tech:jenkins":   [("exploit", "jenkins_script"), ("exploit", "cve_match")],
    "tech:apache":    [("web", "backup"), ("exploit", "cve_match")],
    "tech:nginx":     [("web", "backup"), ("bypass", "403_bypass")],

    "endpoints:api":      [("web", "api_fuzzer_v2"), ("web", "jwt"),
                           ("web", "cors"), ("web", "graphql_attack")],
    "endpoints:swagger":  [("web", "api_fuzzer_v2"), ("web", "jwt")],
    "endpoints:graphql":  [("web", "graphql_attack")],
    "params:found":       [("web", "sqli"), ("web", "xss"), ("web", "lfi"),
                           ("web", "ssti"), ("web", "ssrf"), ("web", "open_redirect")],
    "admin:found":        [("web", "sqli_post"), ("exploit", "default_creds"), ("bypass", "403_bypass")],
    "backup:found":       [("web", "api_leak"), ("dump", "lfi_dump")],

    # "any" — быстрые модули, которые всегда полезны
    "any": [("web", "cookie"), ("web", "backup"), ("web", "api_leak")],

    # Медленные web — только при наличии эндпоинтов
    "endpoints:api": [
        ("web", "cors"),
        ("web", "jwt"),
        ("web", "api_fuzzer_v2"),
        ("web", "graphql_attack"),
    ],
}


CHAIN_TRIGGERS = {
    "sqli_error":        [("dump", "sqli_dump")],
    "sqli_boolean":      [("dump", "sqli_dump")],
    "sqli_time":         [("dump", "sqli_dump")],
    "sqli_union":        [("dump", "sqli_dump")],
    "sqli_post_error":   [("dump", "sqli_post_dump")],
    "sqli_post_bypass":  [("dump", "sqli_post_dump")],
    "lfi":               [("dump", "lfi_dump")],
    "ssrf":              [("dump", "ssrf_dump")],
    "xxe":               [("dump", "xxe_dump")],
    "rce":               [("dump", "rce_dump")],
    "jwt_found":         [("web", "jwt_bypass")],
    "cve_match":         [("exploit", "cve_chain")],
}


class AdaptivePlanner:
    # Auto-extra: модули, требующие явных аргументов
    # sqli_post v3 авто-дискавер, поэтому не нужен
    AUTO_EXTRA = {}

    MODULE_LIMITS = {
        ("recon", "subdomain_brute"): "limit=500",
        ("recon", "crt_sh"): "limit=200",
        ("web", "api_fuzzer_v2"): "limit=100",
        ("web", "template_scan"): "limit=200",
    }

    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        self.loader = ModuleLoader()
        self.executed = []

    def _run(self, cat, mod):
        m = self.loader.load(cat, mod)
        if not m:
            print(f"    x {cat}/{mod} not found")
            return False

        old_extra = list(self.session.extra)
        extra_list = list(self.AUTO_EXTRA.get((cat, mod)) or [])
        limit = self.MODULE_LIMITS.get((cat, mod))
        if limit:
            extra_list.append(limit)
        if extra_list:
            self.session.extra = old_extra + extra_list
            print(f"    [extra: {extra_list}]")

        before = len(self.session.findings)
        try:
            m.run(self.session, self.logger)
        except Exception as e:
            print(f"    x {cat}/{mod}: {type(e).__name__}: {str(e)[:80]}")
            self.executed.append((cat, mod, "error"))
            return False
        finally:
            self.session.extra = old_extra

        after = len(self.session.findings)
        produced = after - before
        self.executed.append((cat, mod, "ok"))
        return produced > 0


    def _analyze_recon(self):
        tags = set()
        details = " ".join(f.get("detail", "") for f in self.session.findings).lower()
        kinds = set(f.get("kind", "") for f in self.session.findings)

        for waf in ["cloudflare", "akamai", "imperva", "f5", "sucuri", "aws"]:
            if waf in details: tags.add(f"waf:{waf}")
        for cms in ["wordpress", "drupal", "joomla", "magento", "opencart", "bitrix"]:
            if cms in details: tags.add(f"cms:{cms}")
        for tech in ["php", "asp.net", "spring", "jenkins", "apache", "nginx",
                     "tomcat", "iis", "node", "django", "rails", "log4j"]:
            if tech in details: tags.add(f"tech:{tech}")
        if any("api" in k or "swagger" in k or "graphql" in k for k in kinds):
            tags.add("endpoints:api")
        if any("swagger" in k for k in kinds): tags.add("endpoints:swagger")
        if any("graphql" in k for k in kinds): tags.add("endpoints:graphql")
        if any("admin" in str(f.get("detail", "")).lower() for f in self.session.findings):
            tags.add("admin:found")
        if "params" in details or "param" in kinds: tags.add("params:found")
        if "backup" in kinds or "exposed_file" in kinds: tags.add("backup:found")
        return tags

    def _build_plan(self, tags):
        plan, seen = [], set()
        for step in RULES["any"]:
            if step not in seen:
                plan.append(step); seen.add(step)
        for tag in tags:
            for step in RULES.get(tag, []):
                if step not in seen:
                    plan.append(step); seen.add(step)
        return plan

    def _check_chains(self):
        added = []
        kinds = set(f.get("kind", "") for f in self.session.findings)
        done = set((c, m) for c, m, _ in self.executed)
        for kind in kinds:
            if kind in CHAIN_TRIGGERS:
                for step in CHAIN_TRIGGERS[kind]:
                    if step not in done and step not in added:
                        added.append(step)
        return added

    def run(self, recon_only=False, max_attack=30):
        print("=" * 70)
        print(f"  ADAPTIVE PIPELINE - {self.session.target}")
        print("=" * 70)

        print(f"\n[Phase 1] RECON ({len(RECON_PHASE)})")
        print("-" * 70)
        for cat, mod in RECON_PHASE:
            print(f"  -> {cat}/{mod}")
            self._run(cat, mod)

        print(f"\n[Analysis]")
        print("-" * 70)
        tags = self._analyze_recon()
        if tags:
            print(f"  Теги: {sorted(tags)}")
        else:
            print(f"  Ничего специфичного")

        if recon_only:
            print(f"\n[recon_only] Findings: {len(self.session.findings)}")
            return {"tags": sorted(tags), "executed": self.executed,
                    "findings": len(self.session.findings)}

        plan = self._build_plan(tags)[:max_attack]
        print(f"\n[Phase 2] ATTACK ({len(plan)})")
        print("-" * 70)
        for i, (cat, mod) in enumerate(plan, 1):
            print(f"  [{i:2d}/{len(plan)}] {cat}/{mod}")
            self._run(cat, mod)

        chains = self._check_chains()
        if chains:
            print(f"\n[Phase 3] CHAINS ({len(chains)})")
            print("-" * 70)
            for cat, mod in chains:
                print(f"  -> {cat}/{mod}")
                self._run(cat, mod)
        else:
            print(f"\n[Phase 3] Нет триггеров")

        print()
        print("=" * 70)
        print(f"  ИТОГО: {len(self.executed)} модулей, {len(self.session.findings)} findings")
        print("=" * 70)
        by_sev = {}
        for f in self.session.findings:
            sev = f.get("severity", "info")
            by_sev[sev] = by_sev.get(sev, 0) + 1
        for sev in ("critical", "high", "medium", "low", "info"):
            if by_sev.get(sev):
                print(f"    {sev:10s}: {by_sev[sev]}")

        return {"tags": sorted(tags), "executed": self.executed,
                "findings": len(self.session.findings)}
