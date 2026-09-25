"""Test session and logger."""
import tempfile
from pathlib import Path
from core.session import Session
from core.logger import Logger


def test_session_creation():
    s = Session(target="http://example.com")
    assert s.target == "http://example.com"


def test_session_finding():
    s = Session(target="http://example.com")
    s.add_finding("test_kind", "high", "test_detail")
    assert len(s.findings) == 1
    assert s.findings[0]["kind"] == "test_kind"


def test_logger_writes():
    s = Session(target="http://example.com")
    with tempfile.TemporaryDirectory() as td:
        l = Logger(s, log_dir=td)
        l.info("test", value=1)
        l.finding("test", "high", "detail")
        l.close()
        files = list(Path(td).glob("*.jsonl"))
        assert len(files) == 1
