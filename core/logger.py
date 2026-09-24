# core/logger.py — jsonl logger with step reporting
import json, time, sys
from pathlib import Path


class Logger:
    def __init__(self, session, log_dir="logs"):
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        self.path = Path(log_dir) / f"{ts}.jsonl"
        self.session = session
        self._fh = self.path.open("a", encoding="utf-8")
        self.step_counter = 0

    def _write(self, level, msg, **kw):
        rec = {"ts": time.time(), "level": level, "msg": msg, **kw}
        self._fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self._fh.flush()

    def info(self, msg, **kw):  self._write("info", msg, **kw)
    def warn(self, msg, **kw):  self._write("warn", msg, **kw)
    def error(self, msg, **kw): self._write("error", msg, **kw)
    def debug(self, msg, **kw): self._write("debug", msg, **kw)

    def finding(self, kind, severity, detail, **kw):
        self._write("finding", kind, severity=severity, detail=detail, **kw)
        self.session.add_finding(kind, severity, detail, **kw)

    def step(self, name, status, detail=""):
        """
        Отчёт по шагу. status: 'pass' | 'fail' | 'info' | 'skip'
        Печатает сразу, чтобы видеть в реальном времени.
        """
        self.step_counter += 1
        icons = {"pass": "✓", "fail": "·", "info": "→", "skip": "–"}
        icon = icons.get(status, "?")
        line = f"  {icon} {name}"
        if detail:
            line += f" — {detail}"
        print(line, flush=True)
        self._write("step", name, status=status, detail=detail, n=self.step_counter)

    def close(self): self._fh.close()
