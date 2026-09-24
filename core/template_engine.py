# core/template_engine.py — Nuclei-compatible template engine
import re, json
from pathlib import Path
from core.http import HttpClient

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


def load_template(path):
    """Load a YAML template (Nuclei format subset)."""
    try:
        import yaml
    except ImportError:
        # простой fallback без yaml
        text = Path(path).read_text()
        return parse_simple_yaml(text)
    with open(path) as f:
        return yaml.safe_load(f)


def parse_simple_yaml(text):
    """Very basic YAML parser for Nuclei templates (no external deps)."""
    out = {"info": {}, "requests": [], "http": []}
    section = None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("id:"):
            out["id"] = s.split(":", 1)[1].strip().strip('"').strip("'")
        elif s.startswith("info:"):
            section = "info"
        elif s.startswith("name:") and section == "info":
            out["info"]["name"] = s.split(":", 1)[1].strip().strip('"').strip("'")
        elif s.startswith("severity:") and section == "info":
            out["info"]["severity"] = s.split(":", 1)[1].strip().strip('"').strip("'")
        elif s.startswith("tags:") and section == "info":
            out["info"]["tags"] = s.split(":", 1)[1].strip()
        elif s.startswith("http:") or s.startswith("requests:"):
            section = "http"
    return out


def match_template(template, http, target, logger=None):
    """Run one template against target. Returns list of findings."""
    findings = []
    info = template.get("info", {})
    name = info.get("name", template.get("id", "?"))
    severity = info.get("severity", "info")

    # handle both 'http' and 'requests' (nuclei v2/v3)
    requests_block = template.get("http") or template.get("requests") or []
    if isinstance(requests_block, dict):
        requests_block = [requests_block]

    for req in requests_block:
        method = req.get("method", "GET").upper()
        paths = req.get("path", [])
        if isinstance(paths, str):
            paths = [paths]
        headers = req.get("headers", {})
        body = req.get("body")
        matchers = req.get("matchers", [])

        for path in paths:
            # substitute variables
            p = path.replace("{{BaseURL}}", target.rstrip("/"))
            p = p.replace("{{Hostname}}", target.split("//")[-1].split("/")[0])
            url = p if p.startswith("http") else target.rstrip("/") + "/" + p.lstrip("/")

            try:
                if method == "GET":
                    r = http.get(url, headers=headers)
                elif method == "POST":
                    r = http.post(url, headers=headers, data=body)
                else:
                    r = http._req(method, url, headers=headers, data=body)
            except Exception:
                continue

            if not r:
                continue

            # check matchers
            for m in matchers:
                m_type = m.get("type", "word")
                m_part = m.get("part", "body")
                m_condition = m.get("condition", "or")

                # pick part
                if m_part == "body":
                    haystack = r.text
                elif m_part == "header":
                    haystack = str(r.headers)
                elif m_part == "status":
                    haystack = str(r.status_code)
                else:
                    haystack = r.text

                words = m.get("words", [])
                regexes = m.get("regex", [])
                statuses = m.get("status", [])

                hit = False
                if m_type == "word":
                    for w in (words if isinstance(words, list) else [words]):
                        if w in haystack:
                            hit = True
                            break
                elif m_type == "regex":
                    for rx in (regexes if isinstance(regexes, list) else [regexes]):
                        if re.search(rx, haystack):
                            hit = True
                            break
                elif m_type == "status":
                    if r.status_code in statuses:
                        hit = True

                if hit:
                    findings.append({
                        "template_id": template.get("id", "?"),
                        "name": name,
                        "severity": severity,
                        "url": url,
                        "code": r.status_code,
                    })
                    if logger:
                        logger.finding(f"template_{severity}", severity,
                                       f"{name} at {url}")
                    break  # one hit per request is enough

    return findings
