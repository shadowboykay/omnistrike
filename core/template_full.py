# core/template_full.py — download all Nuclei templates via git clone
import subprocess
import shutil
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
TMP_DIR = Path(__file__).parent.parent / "_nuclei_tmp"


def download_full():
    print("[template_full] cloning Nuclei templates via git...")
    if TMP_DIR.is_dir():
        shutil.rmtree(TMP_DIR)

    try:
        r = subprocess.run(
            ["git", "clone", "--depth", "1",
             "https://github.com/projectdiscovery/nuclei-templates.git",
             str(TMP_DIR)],
            capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            print(f"  ✗ git clone failed: {r.stderr[:200]}")
            return 0
    except Exception as e:
        print(f"  ✗ {type(e).__name__}: {e}")
        return 0

    count = 0
    for ext in ("*.yaml", "*.yml"):
        for p in TMP_DIR.rglob(ext):
            # flatten with category prefix
            parts = p.relative_to(TMP_DIR).parts
            if len(parts) > 1:
                new_name = "_".join(parts[:-1]) + "_" + parts[-1]
            else:
                new_name = parts[-1]
            target = TEMPLATES_DIR / new_name
            if not target.is_file():
                shutil.copy(p, target)
                count += 1

    shutil.rmtree(TMP_DIR, ignore_errors=True)
    total = len(list(TEMPLATES_DIR.glob("*.yaml"))) + len(list(TEMPLATES_DIR.glob("*.yml")))
    print(f"  ✓ {count} new templates, total: {total}")
    return count


if __name__ == "__main__":
    download_full()
