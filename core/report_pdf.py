# core/report_pdf.py — PDF report (no external deps, uses reportlab if available)
import json
from pathlib import Path
from datetime import datetime


def _escape_html(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def write_html_report(session_data, out_path):
    """Fallback: generate HTML that can be printed to PDF from browser."""
    target = session_data.get("target", "?")
    findings = session_data.get("findings", [])
    duration = session_data.get("duration", 0)

    by_sev = {}
    for f in findings:
        sev = f.get("severity", "info")
        by_sev.setdefault(sev, []).append(f)

    sev_order = ["critical", "high", "medium", "low", "info"]
    colors = {"critical": "#b71c1c", "high": "#e64a19", "medium": "#f57c00",
              "low": "#388e3c", "info": "#1976d2"}

    html = ['<!doctype html><html><head><meta charset="utf-8">',
            f'<title>OmniStrike Report — {_escape_html(target)}</title>',
            '<style>',
            'body{font-family:Arial,sans-serif;max-width:900px;margin:20px auto;color:#222;line-height:1.5}',
            'h1{border-bottom:3px solid #1976d2;padding-bottom:8px}',
            'h2{margin-top:30px;color:#333}',
            '.meta{color:#666;margin-bottom:20px}',
            'table{border-collapse:collapse;width:100%;margin:15px 0}',
            'th,td{text-align:left;padding:8px;border-bottom:1px solid #ddd}',
            'th{background:#f5f5f5}',
            '.sev{display:inline-block;padding:3px 10px;border-radius:4px;color:#fff;font-size:12px;font-weight:bold}',
            '.finding{margin:10px 0;padding:12px;background:#fafafa;border-left:4px solid #ccc}',
            'code{background:#eee;padding:2px 6px;border-radius:3px;font-size:13px}',
            '@media print { body { max-width: none } }',
            '</style></head><body>',
            f'<h1>OmniStrike v2 — Penetration Test Report</h1>',
            f'<div class="meta">',
            f'<b>Target:</b> <code>{_escape_html(target)}</code><br>',
            f'<b>Date:</b> {datetime.now().strftime("%Y-%m-%d %H:%M")}<br>',
            f'<b>Duration:</b> {duration:.1f}s<br>',
            f'<b>Total findings:</b> {len(findings)}',
            f'</div>',
            '<h2>Executive Summary</h2>',
            '<table><tr><th>Severity</th><th>Count</th></tr>']

    for sev in sev_order:
        n = len(by_sev.get(sev, []))
        if n:
            html.append(f'<tr><td><span class="sev" style="background:{colors[sev]}">{sev}</span></td><td>{n}</td></tr>')
    html.append('</table>')

    html.append('<h2>Detailed Findings</h2>')
    for sev in sev_order:
        items = by_sev.get(sev, [])
        if not items:
            continue
        html.append(f'<h3><span class="sev" style="background:{colors[sev]}">{sev}</span> ({len(items)})</h3>')
        for f in items:
            kind = _escape_html(f.get("kind", "?"))
            detail = _escape_html(f.get("detail", ""))
            html.append(f'<div class="finding"><b>{kind}</b><br>{detail}</div>')

    html.append('</body></html>')
    Path(out_path).write_text("\n".join(html))
    return out_path


def convert_to_pdf(html_path, pdf_path):
    """Try to convert HTML to PDF using available tools."""
    import subprocess
    # try weasyprint
    try:
        r = subprocess.run(["weasyprint", str(html_path), str(pdf_path)],
                           capture_output=True, timeout=60)
        if r.returncode == 0:
            return pdf_path
    except Exception:
        pass
    # try wkhtmltopdf
    try:
        r = subprocess.run(["wkhtmltopdf", str(html_path), str(pdf_path)],
                           capture_output=True, timeout=60)
        if r.returncode == 0:
            return pdf_path
    except Exception:
        pass
    return None


def generate(session, logger, out_dir="reports"):
    """Generate PDF report from session. Falls back to HTML."""
    out_dir = Path(out_dir)
    out_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() else "_" for c in session.target)[:60]

    data = {
        "target": session.target,
        "duration": __import__("time").time() - session.started_at,
        "findings": session.findings,
    }

    html_path = out_dir / f"{ts}_{safe}.html"
    write_html_report(data, html_path)

    pdf_path = out_dir / f"{ts}_{safe}.pdf"
    converted = convert_to_pdf(html_path, pdf_path)

    if converted:
        print(f"[report] PDF -> {pdf_path}")
        return str(pdf_path)
    else:
        print(f"[report] PDF не создан (нет weasyprint/wkhtmltopdf)")
        print(f"[report] HTML -> {html_path}")
        print(f"[report] Открой HTML в браузере → Ctrl+P → Save as PDF")
        return str(html_path)
