# core/diff.py — compare two scans: what changed
import json
from pathlib import Path


def load_scan(path):
    return json.loads(Path(path).read_text())


def fingerprint(finding):
    """Unique fingerprint for a finding (kind + detail hash)."""
    import hashlib
    key = f"{finding.get('kind','')}:{finding.get('detail','')[:200]}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


def diff_scans(old_path, new_path):
    """Compare two scans. Returns new/removed/persistent findings."""
    old = load_scan(old_path)
    new = load_scan(new_path)

    old_fps = {fingerprint(f): f for f in old.get("findings", [])}
    new_fps = {fingerprint(f): f for f in new.get("findings", [])}

    new_findings = [new_fps[fp] for fp in new_fps if fp not in old_fps]
    removed_findings = [old_fps[fp] for fp in old_fps if fp not in new_fps]
    persistent = [new_fps[fp] for fp in new_fps if fp in old_fps]

    print(f"[diff] {old_path} -> {new_path}")
    print(f"  NEW:        {len(new_findings)}")
    print(f"  REMOVED:    {len(removed_findings)}")
    print(f"  PERSISTENT: {len(persistent)}")

    if new_findings:
        print(f"\n=== NEW findings ===")
        for f in new_findings:
            print(f"  + [{f.get('severity','info'):8s}] {f.get('kind')}: {f.get('detail','')[:80]}")

    if removed_findings:
        print(f"\n=== REMOVED (fixed) ===")
        for f in removed_findings:
            print(f"  - [{f.get('severity','info'):8s}] {f.get('kind')}: {f.get('detail','')[:80]}")

    return {
        "new": new_findings,
        "removed": removed_findings,
        "persistent": persistent,
    }


def diff_latest_two():
    """Diff two latest scans in reports/."""
    reports = sorted(Path("reports").glob("*.json"), key=lambda p: p.stat().st_mtime)
    if len(reports) < 2:
        print("[diff] need at least 2 scans")
        return None
    return diff_scans(reports[-2], reports[-1])


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3:
        diff_scans(sys.argv[1], sys.argv[2])
    else:
        diff_latest_two()
