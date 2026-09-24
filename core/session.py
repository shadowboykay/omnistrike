# core/session.py — shared state
import json, time
from pathlib import Path
from dataclasses import dataclass, field, asdict

@dataclass
class Session:
    target: str
    proxy: str | None = None
    timeout: int = 10
    user_agent: str | None = None
    threads: int = 10
    output: str | None = None
    extra: list = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    findings: list = field(default_factory=list)
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    def add_finding(self, kind, severity, detail, **kw):
        self.findings.append({"kind":kind,"severity":severity,"detail":detail,"ts":time.time(),**kw})

    def to_dict(self):
        d = asdict(self); d["duration"] = time.time() - self.started_at; return d

    def save(self, path):
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False))
