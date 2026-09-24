# core/version_match.py — semver range matching for CVE applicability
import re
from typing import Optional


def parse_version(v):
    """Parse version string into tuple of ints. Returns (major, minor, patch, ...)."""
    if not v:
        return None
    # strip non-version prefix
    v = v.strip().lstrip("vV")
    # keep only digits and dots
    m = re.match(r"^(\d+(?:\.\d+)*)", v)
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def cmp_version(a, b):
    """Compare two version tuples. Pad shorter one with zeros."""
    if a is None or b is None:
        return None
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    if a < b: return -1
    if a > b: return 1
    return 0


def in_range(target_version, operator, bound_version):
    """
    Check if target_version satisfies the constraint.
    operator: '<' | '<=' | '>' | '>=' | '==' | '='
    """
    t = parse_version(target_version)
    b = parse_version(bound_version)
    if t is None or b is None:
        return False
    c = cmp_version(t, b)
    if c is None:
        return False
    return {
        "<": c < 0,
        "<=": c <= 0,
        ">": c > 0,
        ">=": c >= 0,
        "==": c == 0,
        "=": c == 0,
    }.get(operator, False)


def parse_cpe(cpe):
    """Parse CPE 2.3 string -> dict {vendor, product, version}."""
    # cpe:2.3:a:vendor:product:version:...
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5] if parts[5] not in ("*", "-") else None,
    }


def matches_cpe_version(target_version, cpe_match):
    """
    Check if target_version fits a cpe_match with versionStartIncluding, etc.
    cpe_match: NVD cpeMatch entry with:
      - criteria (CPE)
      - versionStartIncluding / versionStartExcluding
      - versionEndIncluding / versionEndExcluding
    """
    tv = parse_version(target_version)
    if tv is None:
        return False
    # if criteria has concrete version, compare directly
    cpe = parse_cpe(cpe_match.get("criteria", ""))
    if cpe and cpe.get("version"):
        return cmp_version(tv, parse_version(cpe["version"])) == 0
    # range checks
    v_si = cpe_match.get("versionStartIncluding")
    v_se = cpe_match.get("versionStartExcluding")
    v_ei = cpe_match.get("versionEndIncluding")
    v_ee = cpe_match.get("versionEndExcluding")
    if v_si and cmp_version(tv, parse_version(v_si)) < 0:
        return False
    if v_se and cmp_version(tv, parse_version(v_se)) <= 0:
        return False
    if v_ei and cmp_version(tv, parse_version(v_ei)) > 0:
        return False
    if v_ee and cmp_version(tv, parse_version(v_ee)) >= 0:
        return False
    return bool(v_si or v_se or v_ei or v_ee)


# === test ===
if __name__ == "__main__":
    tests = [
        ("2.4.49", "<", "2.4.50", True),
        ("2.4.50", "<=", "2.4.50", True),
        ("2.4.51", "<", "2.4.50", False),
        ("8.5.1", "==", "8.5.1", True),
        ("1.0", ">=", "2.0", False),
    ]
    for tv, op, bv, expected in tests:
        result = in_range(tv, op, bv)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {tv} {op} {bv} -> {result} (expected {expected})")
