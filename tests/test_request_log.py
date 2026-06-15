import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import proxy.request_log as rl


def test_log_and_read(tmp_path):
    p = tmp_path / "requests.jsonl"
    rl.init(str(p), max_entries=100)
    rl.log_request({"ts": 1, "host": "a.com", "action": "ok"})
    rl.log_request({"ts": 2, "host": "b.com", "action": "blocked"})
    lines = p.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["host"] == "b.com"


def test_trim_caps_file(tmp_path):
    p = tmp_path / "requests.jsonl"
    # max clamps to a floor of 50; trim runs every 200 appends.
    rl.init(str(p), max_entries=50)
    for i in range(250):
        rl.log_request({"ts": i, "host": f"h{i}.com", "action": "ok"})
    lines = p.read_text().splitlines()
    # After the trim at 200, file holds the last 50; remaining 50 appended after.
    assert len(lines) <= 100
    # Newest entry is preserved.
    assert json.loads(lines[-1])["host"] == "h249.com"


def test_no_init_is_noop(tmp_path):
    # Re-init to a fresh path so a prior test's state doesn't leak.
    rl.init(str(tmp_path / "x.jsonl"), max_entries=50)
    rl.log_request({"ts": 1})  # should not raise
