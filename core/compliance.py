# core/compliance.py — compliance checks (CIS Benchmark, PCI-DSS, HIPAA)
from pathlib import Path
from core.http import HttpClient
import re

COMPLIANCE_DIR = Path(__file__).parent.parent / "data" / "compliance"


def load_benchmark(name):
    """Load YAML benchmark (simple parser)."""
    p = COMPLIANCE_DIR / f"{name}.yaml"
    if not p.is_file():
        return None
    text = p.read_text()
    # simple YAML parser
    bench = {"name": "", "version": "", "checks": []}
    current = None
    indent = 0
    for line in text.splitlines():
        s = line.rstrip()
        if not s or s.lstrip().startswith("#"):
            continue
        stripped = s.lstrip()
        ind = len(s) - len(stripped)
        if stripped.startswith("name:") and ind == 0:
            bench["name"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("version:") and ind == 0:
            bench["version"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("- id:"):
            current = {"id": stripped.split(":", 1)[1].strip()}
            bench["checks"].append(current)
        elif current is not None and ":" in stripped:
            k, _, v = stripped.partition(":")
            k = k.strip().lstrip("- ").strip()
            v = v.strip().strip('"').strip("'")
            if k == "check":
                current["check"] = {}
            elif k in ("type", "header", "pattern", "value", "path", "expected_not"):
                if "check" not in current:
                    current["check"] = {}
                current["check"][k] = v
            elif k in ("title", "description", "severity"):
                current[k] = v
    return bench


def run_check(check, http, target):
    """Run one compliance check."""
    t = check.get("check", {})
    ctype = t.get("type")

    if ctype == "header_present":
        r = http.get(target)
        if not r:
            return None, "no response"
        header = t.get("header")
        expected_value = t.get("value")
        actual = r.headers.get(header)
        if actual and (not expected_value or expected_value in actual):
            return True, f"{header}: {actual[:40]}"
        return False, f"missing: {header}"

    if ctype == "header_absent":
        r = http.get(target)
        if not r:
            return None, "no response"
        header = t.get("header")
        actual = r.headers.get(header)
        if actual:
            return False, f"{header}: {actual}"
        return True, "not present"

    if ctype == "header_not_contains":
        r = http.get(target)
        if not r:
            return None, "no response"
        header = t.get("header")
        pattern = t.get("pattern", "")
        actual = r.headers.get(header, "")
        if re.search(pattern, actual):
            return False, f"{header} contains pattern: {actual[:50]}"
        return True, f"{header}: clean"

    if ctype == "https_redirect":
        if not target.startswith("https://"):
            http_url = target.replace("http://", "https://")
            r = http.get(target)
            if r and r.status_code in (301, 302, 307, 308):
                loc = r.headers.get("Location", "")
                if "https" in loc:
                    return True, f"redirects to {loc[:40]}"
            return False, "no HTTPS redirect"
        return True, "already HTTPS"

    if ctype == "cookie_secure":
        r = http.get(target)
        if not r:
            return None, "no response"
        if not r.cookies:
            return True, "no cookies"
        missing = [c.name for c in r.cookies if not c.secure]
        if missing:
            return False, f"cookies without Secure: {missing}"
        return True, "all Secure"

    if ctype == "cookie_httponly":
        r = http.get(target)
        if not r:
            return None, "no response"
        if not r.cookies:
            return True, "no cookies"
        missing = [c.name for c in r.cookies if "httponly" not in str(c._rest).lower()]
        if missing:
            return False, f"cookies without HttpOnly: {missing}"
        return True, "all HttpOnly"

    if ctype == "cookie_samesite":
        r = http.get(target)
        if not r:
            return None, "no response"
        if not r.cookies:
            return True, "no cookies"
        missing = [c.name for c in r.cookies if "samesite" not in str(c._rest).lower()]
        if missing:
            return False, f"cookies without SameSite: {missing}"
        return True, "all SameSite"

    if ctype == "path_status":
        path = t.get("path")
        expected_not = int(t.get("expected_not", 200))
        r = http.get(target.rstrip("/") + path)
        if not r:
            return True, "no response"
        if r.status_code == expected_not:
            return False, f"{path} returned {r.status_code}"
        return True, f"{path}: {r.status_code}"

    if ctype == "body_not_contains":
        path = t.get("path", "/")
        pattern = t.get("pattern", "")
        r = http.get(target.rstrip("/") + path)
        if not r:
            return None, "no response"
        if pattern in r.text:
            return False, f"{path} contains pattern"
        return True, "clean"

    if ctype == "custom_404":
        import random
        r = http.get(target.rstrip("/") + f"/nonexistent-{random.randint(10000,99999)}")
        if r and r.status_code == 200:
            return False, "soft 404"
        return True, "proper 404"

    return None, "unsupported check"
