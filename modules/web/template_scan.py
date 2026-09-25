"""template_scan — Nuclei-compatible template runner"""
from core.http import HttpClient
from core.template_engine_v2 import load_template_v2 as load_template, match_template_v2 as match_template
from pathlib import Path
import random

TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates"


class TemplateScan:
    def run(self, session, logger):
        target = session.target
        http = HttpClient(session, logger)
        print(f"[template_scan] target: {target}")

        # filter options from --extra
        sev_filter = None
        tag_filter = None
        limit = None
        for x in session.extra:
            if x.startswith("severity="):
                sev_filter = x.split("=", 1)[1].split(",")
            elif x.startswith("tag="):
                tag_filter = x.split("=", 1)[1]
            elif x.startswith("limit="):
                limit = int(x.split("=", 1)[1])

        # list templates
        templates = list(TEMPLATES_DIR.rglob("*.yaml")) + list(TEMPLATES_DIR.rglob("*.yml"))
        print(f"[template_scan] {len(templates)} templates available")

        if not templates:
            print("  запусти: python -c 'from core.template_updater import download_templates; download_templates()'")
            return {"templates": 0}

        random.shuffle(templates)
        if limit:
            templates = templates[:limit]

        findings = []
        tested = 0
        matched = 0

        for i, path in enumerate(templates, 1):
            try:
                tpl = load_template(path)
            except Exception:
                continue

            info = tpl.get("info", {})
            sev = info.get("severity", "info").lower()

            if sev_filter and sev not in sev_filter:
                continue
            if tag_filter and tag_filter not in str(info.get("tags", "")):
                continue

            tested += 1
            try:
                f = match_template(tpl, http, target, logger)
                if f:
                    matched += 1
                    for item in f:
                        print(f"  ✓ [{item['severity']}] {item['name'][:60]}")
                    findings.extend(f)
            except Exception:
                continue

            if i % 100 == 0:
                print(f"  · tested {i}/{len(templates)}, matched {matched}")

        print(f"\n[template_scan] tested: {tested}, matched: {matched}, findings: {len(findings)}")
        return {"tested": tested, "matched": matched, "findings": findings[:100]}
