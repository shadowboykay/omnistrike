# core/template_updater.py — download Nuclei templates (MIT license)
import json, zipfile, io
from pathlib import Path
import requests
import urllib3
urllib3.disable_warnings()

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
TEMPLATES_DIR.mkdir(exist_ok=True)

# Nuclei templates repo (official, MIT)
NUCLEI_REPO = "https://github.com/projectdiscovery/nuclei-templates"
NUCLEI_ZIP = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"


def download_templates():
    print("[templates] downloading Nuclei templates...")
    try:
        r = requests.get(NUCLEI_ZIP, timeout=120, stream=True, verify=False)
        if r.status_code != 200:
            print(f"  ✗ download failed: {r.status_code}")
            return 0
        total = int(r.headers.get("content-length", 0))
        print(f"  size: {total / 1024 / 1024:.1f} MB")
        zdata = io.BytesIO()
        for chunk in r.iter_content(8192):
            zdata.write(chunk)
        zdata.seek(0)
        with zipfile.ZipFile(zdata) as z:
            count = 0
            for name in z.namelist():
                if name.endswith((".yaml", ".yml")):
                    target_path = TEMPLATES_DIR / Path(name).name
                    with z.open(name) as src:
                        target_path.write_bytes(src.read())
                    count += 1
        print(f"  ✓ extracted {count} templates")
        return count
    except Exception as e:
        print(f"  ✗ {type(e).__name__}: {e}")
        return 0


def count_by_severity():
    counts = {}
    for p in TEMPLATES_DIR.glob("*.yaml"):
        try:
            text = p.read_text(errors="ignore")
            for line in text.splitlines()[:50]:
                if line.strip().startswith("severity:"):
                    sev = line.split(":", 1)[1].strip().strip('"').strip("'")
                    counts[sev] = counts.get(sev, 0) + 1
                    break
        except Exception:
            pass
    return counts


if __name__ == "__main__":
    n = download_templates()
    print(f"\nTotal templates: {n}")
    print("By severity:", count_by_severity())
