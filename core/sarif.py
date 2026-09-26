# core/sarif.py — SARIF 2.1.0 report (GitHub Security tab compatible)
import json
from pathlib import Path
from datetime import datetime


SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def to_sarif(session, out_path):
    """Generate SARIF 2.1.0 report."""
    target = session.target
    findings = session.findings

    results = []
    rules = {}
    for f in findings:
        kind = f.get("kind", "unknown")
        sev = f.get("severity", "info")
        detail = f.get("detail", "")

        if kind not in rules:
            rules[kind] = {
                "id": kind,
                "name": kind,
                "shortDescription": {"text": kind},
                "fullDescription": {"text": f"OmniStrike finding: {kind}"},
                "defaultConfiguration": {"level": SEVERITY_MAP.get(sev, "note")},
            }

        results.append({
            "ruleId": kind,
            "level": SEVERITY_MAP.get(sev, "note"),
            "message": {"text": detail},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target},
                }
            }],
            "properties": {
                "severity": sev,
            }
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OmniStrike",
                    "version": "2.0",
                    "informationUri": "https://github.com/omnistrike",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }]
    }

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(sarif, indent=2))
    return out_path


def generate(session, out_dir="reports"):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() else "_" for c in session.target)[:60]
    out = Path(out_dir) / f"{ts}_{safe}.sarif"
    to_sarif(session, out)
    print(f"[sarif] -> {out}")
    return str(out)
