# core/report.py — reporter: json + md + html, group by severity/kind
import json, time, html
from pathlib import Path
from collections import defaultdict


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Reporter:
    def __init__(self, session, logger, out_dir="reports"):
        self.session = session
        self.logger = logger
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def write(self, result=None):
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe = "".join(c if c.isalnum() else "_" for c in self.session.target)[:60]
        base = self.out_dir / f"{ts}_{safe}"

        findings = self.session.findings
        by_sev = defaultdict(list)
        by_kind = defaultdict(list)
        for f in findings:
            by_sev[f.get("severity", "info")].append(f)
            by_kind[f.get("kind", "unknown")].append(f)

        # ---- JSON ----
        payload = {
            "target": self.session.target,
            "started_at": self.session.started_at,
            "duration": time.time() - self.session.started_at,
            "counts": {
                "total": len(findings),
                **{sev: len(by_sev.get(sev, [])) for sev in SEVERITY_ORDER},
            },
            "findings": sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity","info"), 99)),
            "result": result or {},
        }
        base.with_suffix(".json").write_text(json.dumps(payload, indent=2, ensure_ascii=False))

        # ---- MD ----
        md = []
        md.append(f"# OmniStrike report — `{self.session.target}`")
        md.append("")
        md.append(f"**Duration:** {payload['duration']:.1f}s  ")
        md.append(f"**Total findings:** {len(findings)}")
        md.append("")
        md.append("## Summary by severity")
        md.append("")
        md.append("| severity | count |")
        md.append("|---|---|")
        for sev in SEVERITY_ORDER:
            md.append(f"| {sev} | {len(by_sev.get(sev, []))} |")
        md.append("")
        md.append("## Summary by type")
        md.append("")
        md.append("| kind | count |")
        md.append("|---|---|")
        for kind, items in sorted(by_kind.items(), key=lambda x: -len(x[1])):
            md.append(f"| {kind} | {len(items)} |")
        md.append("")
        md.append("## Details")
        md.append("")
        for sev in SEVERITY_ORDER:
            items = by_sev.get(sev, [])
            if not items: continue
            md.append(f"### {sev.upper()} ({len(items)})")
            md.append("")
            for f in items:
                md.append(f"- **{f['kind']}** — {f['detail']}")
            md.append("")
        if result:
            md.append("## Raw result")
            md.append("")
            md.append("```json")
            md.append(json.dumps(result, indent=2, ensure_ascii=False)[:5000])
            md.append("```")
        base.with_suffix(".md").write_text("\n".join(md))

        # ---- HTML ----
        html_doc = self._html(payload, by_sev, by_kind)
        base.with_suffix(".html").write_text(html_doc)

        # ---- console ----
        print(f"[omni] report json -> {base.with_suffix('.json')}")
        print(f"[omni] report md   -> {base.with_suffix('.md')}")
        print(f"[omni] report html -> {base.with_suffix('.html')}")
        print(f"[omni] findings: {len(findings)}")
        for sev in SEVERITY_ORDER:
            n = len(by_sev.get(sev, []))
            if n: print(f"        {sev:8s}: {n}")
        self.logger.info("report_written", path=str(base))

    def _html(self, payload, by_sev, by_kind):
        colors = {"critical":"#b71c1c","high":"#e64a19","medium":"#f57c00","low":"#388e3c","info":"#1976d2"}
        parts = [
            "<!doctype html><html><head><meta charset='utf-8'>",
            f"<title>OmniStrike — {html.escape(payload['target'])}</title>",
            "<style>",
            "body{font-family:system-ui,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;color:#222}",
            "h1{margin:0 0 4px 0}",
            ".meta{color:#666;font-size:14px;margin-bottom:24px}",
            "table{border-collapse:collapse;width:100%;margin:8px 0 24px 0}",
            "th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #eee}",
            "th{background:#f7f7f7}",
            ".sev{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:12px;font-weight:600}",
            ".finding{padding:8px 12px;border-left:4px solid #ccc;margin:6px 0;background:#fafafa}",
            ".finding code{background:#eee;padding:1px 4px;border-radius:3px}",
            "</style></head><body>",
            f"<h1>OmniStrike report</h1>",
            f"<div class='meta'>target: <code>{html.escape(payload['target'])}</code> · duration: {payload['duration']:.1f}s · findings: {len(payload['findings'])}</div>",
        ]
        parts.append("<h2>By severity</h2><table><tr><th>Severity</th><th>Count</th></tr>")
        for sev in SEVERITY_ORDER:
            n = len(by_sev.get(sev, []))
            if not n: continue
            c = colors[sev]
            parts.append(f"<tr><td><span class='sev' style='background:{c}'>{sev}</span></td><td>{n}</td></tr>")
        parts.append("</table>")

        parts.append("<h2>By type</h2><table><tr><th>Kind</th><th>Count</th></tr>")
        for kind, items in sorted(by_kind.items(), key=lambda x: -len(x[1])):
            parts.append(f"<tr><td>{html.escape(kind)}</td><td>{len(items)}</td></tr>")
        parts.append("</table>")

        for sev in SEVERITY_ORDER:
            items = by_sev.get(sev, [])
            if not items: continue
            c = colors[sev]
            parts.append(f"<h2><span class='sev' style='background:{c}'>{sev}</span> ({len(items)})</h2>")
            for f in items:
                parts.append(f"<div class='finding'><b>{html.escape(f['kind'])}</b> — {html.escape(f['detail'])}</div>")

        parts.append("</body></html>")
        return "\n".join(parts)
