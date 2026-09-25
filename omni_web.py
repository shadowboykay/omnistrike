#!/usr/bin/env python3
# omni_web.py — simple web UI for OmniStrike (Flask)
"""
Минимальный web-интерфейс:
  - список модулей
  - запуск модуля
  - просмотр результатов в реальном времени
  - просмотр отчётов
"""
import sys, os, subprocess, json
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

try:
    from flask import Flask, render_template_string, request, redirect, jsonify, send_from_directory
except ImportError:
    print("[!] Flask not installed")
    print("    pip install flask")
    sys.exit(1)

from core.loader import ModuleLoader


app = Flask(__name__)
RUNS = {}  # in-memory runs storage


TEMPLATE_INDEX = """
<!doctype html><html><head><meta charset="utf-8">
<title>OmniStrike Web</title>
<style>
body{font-family:sans-serif;max-width:900px;margin:20px auto;padding:0 20px;background:#f9f9f9}
h1{border-bottom:3px solid #1976d2;padding-bottom:10px}
.cat{margin:20px 0;background:#fff;padding:15px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.cat h3{margin-top:0;color:#1976d2}
.mod{display:inline-block;margin:4px;padding:6px 12px;background:#e3f2fd;border-radius:4px;text-decoration:none;color:#1976d2;font-size:14px}
.mod:hover{background:#bbdefb}
form{background:#fff;padding:20px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);margin:20px 0}
input,select{width:100%;padding:8px;margin:6px 0;border:1px solid #ddd;border-radius:4px;font-size:14px;box-sizing:border-box}
button{padding:10px 20px;background:#1976d2;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px}
button:hover{background:#1565c0}
</style></head><body>
<h1>OmniStrike v2 — Web UI</h1>
<p>{{n_modules}} модулей в {{n_categories}} категориях</p>

<form method="post" action="/run">
  <h3>Запуск</h3>
  <label>Категория</label>
  <select name="category">{% for c in categories %}<option>{{c}}</option>{% endfor %}</select>
  <label>Модуль</label>
  <input name="module" placeholder="например subdomain_brute" required>
  <label>Target</label>
  <input name="target" placeholder="https://example.com" required>
  <label>Extra args (опц)</label>
  <input name="extra" placeholder="creds=user:pass">
  <button>Запустить</button>
</form>

{% for c, mods in by_category.items() %}
<div class="cat">
  <h3>{{c}} ({{mods|length}})</h3>
  {% for name, desc in mods.items() %}
    <a class="mod" href="/module/{{c}}/{{name}}">{{name}}</a>
  {% endfor %}
</div>
{% endfor %}
</body></html>
"""

TEMPLATE_RUN = """
<!doctype html><html><head><meta charset="utf-8">
<title>Run {{run_id}}</title>
<style>
body{font-family:monospace;max-width:1000px;margin:20px auto;padding:0 20px;background:#1e1e1e;color:#ddd}
h1{color:#4fc3f7}
pre{background:#000;padding:15px;border-radius:8px;overflow-x:auto;white-space:pre-wrap}
a{color:#4fc3f7}
</style></head><body>
<h1>Run: {{run_id}}</h1>
<p><a href="/">← Назад</a> | <a href="/results/{{run_id}}">Обновить</a></p>
<pre>{{output}}</pre>
<script>setTimeout(()=>location.reload(), 3000)</script>
</body></html>
"""

TEMPLATE_MODULE = """
<!doctype html><html><head><meta charset="utf-8">
<title>{{name}}</title>
<style>body{font-family:sans-serif;max-width:800px;margin:20px auto;padding:0 20px}a{color:#1976d2}form{background:#fff;padding:20px;border-radius:8px}input{width:100%;padding:8px;margin:6px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}button{padding:10px 20px;background:#1976d2;color:#fff;border:none;border-radius:4px;cursor:pointer}</style>
</head><body>
<h1>{{cat}}/{{name}}</h1>
<p>{{desc}}</p>
<a href="/">← Все модули</a>
<form method="post" action="/run">
  <input type="hidden" name="category" value="{{cat}}">
  <input type="hidden" name="module" value="{{name}}">
  <label>Target</label>
  <input name="target" placeholder="https://example.com" required>
  <label>Extra</label>
  <input name="extra">
  <button>Запустить</button>
</form>
</body></html>
"""


@app.route("/")
def index():
    loader = ModuleLoader()
    by_cat = {}
    total = 0
    for cat in ["recon","web","bypass","exploit","evasion","c2",
                "post","osint","mobile","cloud","ad","dump"]:
        mods = loader.list_category(cat)
        if mods:
            by_cat[cat] = mods
            total += len(mods)
    return render_template_string(TEMPLATE_INDEX,
                                  by_category=by_cat,
                                  categories=list(by_cat.keys()),
                                  n_modules=total,
                                  n_categories=len(by_cat))


@app.route("/module/<cat>/<name>")
def module_view(cat, name):
    loader = ModuleLoader()
    mods = loader.list_category(cat)
    if name not in mods:
        return "Module not found", 404
    return render_template_string(TEMPLATE_MODULE,
                                  cat=cat, name=name, desc=mods[name])


@app.route("/run", methods=["POST"])
def run_module():
    cat = request.form.get("category")
    mod = request.form.get("module")
    target = request.form.get("target")
    extra = request.form.get("extra", "").strip()

    cmd = [sys.executable, str(ROOT / "omni.py"), "run", cat, mod, "--target", target]
    if extra:
        cmd.extend(["--extra", extra])

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = ROOT / "web_runs" / f"{run_id}.log"
    log_path.parent.mkdir(exist_ok=True)

    with log_path.open("w") as f:
        proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, cwd=ROOT)

    RUNS[run_id] = {"pid": proc.pid, "log": log_path, "cmd": " ".join(cmd)}
    return redirect(f"/run/{run_id}")


@app.route("/run/<run_id>")
def view_run(run_id):
    info = RUNS.get(run_id)
    if not info:
        return "Run not found", 404
    try:
        output = info["log"].read_text()[-8000:]
    except Exception:
        output = "loading..."
    return render_template_string(TEMPLATE_RUN, run_id=run_id, output=output)


@app.route("/results/<run_id>")
def results(run_id):
    info = RUNS.get(run_id)
    if not info:
        return jsonify({"error": "not found"}), 404
    try:
        return jsonify({"output": info["log"].read_text()[-10000:]})
    except Exception:
        return jsonify({"output": "loading"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    print(f"[web] OmniStrike Web UI on http://127.0.0.1:{port}")
    print(f"[web] открывай в браузере")
    app.run(host="127.0.0.1", port=port, debug=False)
