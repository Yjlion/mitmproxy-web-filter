import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from shared.models import Policy, GlobalSettings


def test_policy_defaults():
    p = Policy(name="test")
    assert p.name == "test"
    assert p.source_ips == []
    assert p.source_macs == []
    assert not p.url_filter.enabled
    assert not p.doh.enabled
    assert p.image_classifier.action == "blur"
    assert p.youtube.mode == "blacklist"


def test_policy_roundtrip():
    p = Policy(name="kids", source_ips=["192.168.1.0/24"])
    p.url_filter.enabled = True
    p.url_filter.block = ["bad.com", "*.adult.net"]
    data = p.model_dump_json()
    restored = Policy.model_validate_json(data)
    assert restored.name == "kids"
    assert restored.url_filter.block == ["bad.com", "*.adult.net"]


def test_policy_source_macs_normalized():
    # Mixed separators / case / Cisco dots all canonicalize; junk is dropped.
    p = Policy(name="dev", source_macs=[
        "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "11:22:33:44:55:66", "not-a-mac",
    ])
    assert p.source_macs == [
        "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
    ]
    restored = Policy.model_validate_json(p.model_dump_json())
    assert restored.source_macs == p.source_macs


def test_global_settings_defaults():
    s = GlobalSettings()
    assert s.proxy_listen == ["0.0.0.0:8080"]
    assert s.primary_proxy_port == 8080
    assert s.mgmt_host == "0.0.0.0"
    assert s.mgmt_port == 8000
    assert s.log_blocks is True
    assert s.log_requests is True
    assert s.log_retention_days == 30
    assert s.db_path.endswith("webfilter.db")
