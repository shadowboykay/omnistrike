# core/state.py — scan state for resume
import json
from pathlib import Path
from datetime import datetime

STATE_DIR = Path(__file__).parent.parent / "states"
STATE_DIR.mkdir(exist_ok=True)


def state_path(session):
    safe = "".join(c if c.isalnum() else "_" for c in session.target)[:60]
    return STATE_DIR / f"{safe}.json"


def save(session, module_name=None):
    data = {
        "target": session.target,
        "module": module_name,
        "findings": session.findings,
        "saved_at": datetime.now().isoformat(),
    }
    state_path(session).write_text(json.dumps(data, indent=2, default=str))
    return str(state_path(session))


def load(session):
    p = state_path(session)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def clear(session):
    p = state_path(session)
    if p.is_file():
        p.unlink()


def list_all():
    return sorted(STATE_DIR.glob("*.json"))
