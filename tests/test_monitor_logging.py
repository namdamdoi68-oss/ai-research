import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_monitor():
    spec = importlib.util.spec_from_file_location("monitor", ROOT / "monitor.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sanitize_log_message_escapes_crlf():
    monitor = load_monitor()

    assert monitor.sanitize_log_message("good\r\nfake=entry\nnext") == "good\\r\\nfake=entry\\nnext"


def test_log_writes_one_physical_line_for_crlf_input(tmp_path, monkeypatch):
    monitor = load_monitor()
    log_path = tmp_path / "monitor.log"
    monkeypatch.setattr(monitor, "LOG_FILE", str(log_path))

    monitor.log("user-agent=ok\r\n[FAKE] injected")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert "\\r\\n[FAKE] injected" in lines[0]
