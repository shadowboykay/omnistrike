"""listener — HTTP C2 listener (Flask-based, logs callbacks)"""
import os, json, time
from pathlib import Path

class Listener:
    def run(self, session, logger):
        port = int(os.environ.get("C2_PORT", "8000"))
        log_dir = Path("logs") / "c2"
        log_dir.mkdir(parents=True, exist_ok=True)

        print(f"[c2:listener] starting HTTP listener on 0.0.0.0:{port}")
        print(f"  logs: {log_dir}")
        print()
        print("  # run separately:")
        print(f"  python -c \"from flask import Flask, request; app=Flask(__name__);")
        print(f"  @app.route('/',defaults={{'p':''}}); @app.route('/<path:p>')")
        print(f"  def h(p): open('{log_dir}/beacons.log','a').write(str(dict(request.headers))+chr(10)); return '';")
        print(f"  app.run(host='0.0.0.0',port={port})\"")
        print()

        # write listener script
        script = log_dir / "listener.py"
        script.write_text(f'''
from flask import Flask, request
import json, time
from pathlib import Path
app = Flask(__name__)
LOG = Path("{log_dir}") / "beacons.jsonl"

@app.route("/", defaults={{"p":""}})
@app.route("/<path:p>")
def h(p):
    rec = {{
        "ts": time.time(),
        "path": "/" + p,
        "method": request.method,
        "ip": request.remote_addr,
        "ua": request.headers.get("User-Agent",""),
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True)[:2000],
    }}
    LOG.write_text(LOG.read_text() + json.dumps(rec) + "\\n") if LOG.exists() else LOG.write_text(json.dumps(rec) + "\\n")
    return "OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port={port})
''')
        print(f"  listener script: {script}")
        logger.info("c2_listener", port=port, script=str(script))
        return {"port": port, "script": str(script)}
