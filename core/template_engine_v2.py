# core/template_engine_v2.py — full Nuclei template engine (raw/dsl/matchers-condition)
import re
import json
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


def safe_eval_dsl(expr, ctx):
    """Evaluate simple DSL expressions like: status_code == 200 && contains(body, 'x')"""
    expr = expr.strip()
    # replace contains(body, 'x') with True/False
    def rep_contains(m):
        var = m.group(1).strip()
        val = m.group(2).strip().strip('"').strip("'")
        haystack = str(ctx.get(var, ""))
        return "True" if val in haystack else "False"

    expr = re.sub(r'contains\((\w+),\s*["\']([^"\']*)["\']\)', rep_contains, expr)

    def rep_contains_any(m):
        var = m.group(1).strip()
        vals = re.findall(r'["\']([^"\']*)["\']', m.group(2))
        haystack = str(ctx.get(var, ""))
        return "True" if any(v in haystack for v in vals) else "False"

    expr = re.sub(r'contains_any\((\w+),\s*([^)]+)\)', rep_contains_any, expr)

    # replace variables
    for k, v in ctx.items():
        if isinstance(v, (int, float)):
            expr = re.sub(rf'\b{k}\b', str(v), expr)
        elif isinstance(v, str) and v.isdigit():
            expr = re.sub(rf'\b{k}\b', v, expr)

    # replace && || ! 
    expr = expr.replace("&&", " and ").replace("||", " or ")
    expr = re.sub(r'(?<![<>=!])!(?!=)', ' not ', expr)

    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))
    except Exception:
        return False


def run_matchers(matchers, condition, response):
    """
    Run list of matchers. condition: 'and' | 'or' (default 'or').
    response: {status_code, body, headers, content_length, duration}
    """
    if not matchers:
        return True

    results = []
    for m in matchers:
        m_type = m.get("type", "word")
        m_part = m.get("part", "body")
        m_cond = m.get("condition", "or")  # внутри матчера
        negative = m.get("negative", False)

        if m_part == "body":
            haystack = response.get("body", "")
        elif m_part == "header":
            haystack = str(response.get("headers", ""))
        elif m_part == "status":
            haystack = str(response.get("status_code", ""))
        elif m_part == "all":
            haystack = response.get("body", "") + " " + str(response.get("headers", ""))
        else:
            haystack = response.get("body", "")

        hit = False

        if m_type == "word":
            words = m.get("words", [])
            if isinstance(words, str): words = [words]
            hits = [w for w in words if w in haystack]
            hit = len(hits) > 0 if m_cond == "or" else len(hits) == len(words)

        elif m_type == "regex":
            regexes = m.get("regex", [])
            if isinstance(regexes, str): regexes = [regexes]
            hits = [r for r in regexes if re.search(r, haystack)]
            hit = len(hits) > 0 if m_cond == "or" else len(hits) == len(regexes)

        elif m_type == "status":
            statuses = m.get("status", [])
            if isinstance(statuses, int): statuses = [statuses]
            hit = response.get("status_code") in statuses

        elif m_type == "size":
            sizes = m.get("size", [])
            if isinstance(sizes, int): sizes = [sizes]
            hit = response.get("content_length") in sizes

        elif m_type == "dsl":
            dsl = m.get("dsl", [])
            if isinstance(dsl, str): dsl = [dsl]
            hits = [safe_eval_dsl(d, response) for d in dsl]
            hit = any(hits) if m_cond == "or" else all(hits)

        if negative:
            hit = not hit
        results.append(hit)

    if condition == "and":
        return all(results)
    return any(results)


def parse_template_v2(text):
    """Parse YAML template supporting raw/dsl/matchers-condition."""
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        pass
    # fallback simple parser
    return {"id": "?", "info": {}, "http": []}


def load_template_v2(path):
    """Load and parse template."""
    return parse_template_v2(Path(path).read_text(errors="ignore"))


def execute_http_block(http, target, block):
    """
    Execute one HTTP block (path, raw, or payloads).
    Returns list of (response, meta) tuples.
    """
    results = []
    method = block.get("method", "GET").upper()
    headers = block.get("headers", {})
    body = block.get("body")
    redirects = block.get("redirects", True)
    max_size = block.get("max-size", 0)

    # substitute target
    def subst(s):
        if not isinstance(s, str):
            return s
        s = s.replace("{{BaseURL}}", target.rstrip("/"))
        s = s.replace("{{Hostname}}", target.split("//")[-1].split("/")[0])
        s = s.replace("{{Host}}", target.split("//")[-1].split("/")[0])
        s = s.replace("{{RootURL}}", "/".join(target.rstrip("/").split("/")[:3]))
        return s

    # raw block — full HTTP request
    if "raw" in block:
        raw_reqs = block["raw"] if isinstance(block["raw"], list) else [block["raw"]]
        for raw in raw_reqs:
            raw = subst(raw)
            try:
                lines = raw.split("\n")
                request_line = lines[0].strip()
                parts = request_line.split()
                if len(parts) >= 2:
                    m = parts[0].upper()
                    path = parts[1]
                    url = target.rstrip("/") + (path if path.startswith("/") else "/" + path)
                    try:
                        r = http._req(m, url, headers=headers, data=body)
                        if r:
                            results.append({
                                "response": r,
                                "meta": {"url": url, "method": m}
                            })
                    except Exception:
                        pass
            except Exception:
                pass
        return results

    # path block
    paths = block.get("path", [])
    if isinstance(paths, str):
        paths = [paths]
    for path in paths:
        path = subst(path)
        url = path if path.startswith("http") else target.rstrip("/") + "/" + path.lstrip("/")
        try:
            if method == "GET":
                r = http.get(url, headers=headers, allow_redirects=redirects)
            elif method == "POST":
                r = http.post(url, headers=headers, data=body)
            else:
                r = http._req(method, url, headers=headers, data=body)
            if r:
                results.append({
                    "response": r,
                    "meta": {"url": url, "method": method}
                })
        except Exception:
            continue
    return results


def match_template_v2(template, http, target, logger=None):
    """Execute full template. Supports http + http/raw + dsl + matchers-condition."""
    findings = []
    info = template.get("info", {})
    tid = template.get("id", "?")
    name = info.get("name", tid)
    severity = info.get("severity", "info")

    http_block = template.get("http") or template.get("requests") or []
    if isinstance(http_block, dict):
        http_block = [http_block]

    for block in http_block:
        matchers = block.get("matchers", [])
        matchers_cond = block.get("matchers-condition", "or")
        # run requests
        responses = execute_http_block(http, target, block)

        for resp_data in responses:
            r = resp_data["response"]
            meta = resp_data["meta"]

            ctx = {
                "status_code": r.status_code,
                "body": r.text,
                "headers": str(r.headers),
                "content_length": len(r.content),
            }
            if run_matchers(matchers, matchers_cond, ctx):
                findings.append({
                    "template_id": tid,
                    "name": name,
                    "severity": severity,
                    "url": meta["url"],
                    "method": meta["method"],
                    "code": r.status_code,
                })
                if logger:
                    logger.finding(f"tpl_{severity}", severity,
                                   f"{name} at {meta['url']}")
                break  # one hit per block enough

    return findings
