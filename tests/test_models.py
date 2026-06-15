import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from shared.models import Policy, GlobalSettings


def test_policy_defaults():
    p = Policy(name="test")
    assert p.name == "test"
    assert p.source_ips == []
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


def test_global_settings_defaults():
    s = GlobalSettings()
    assert s.proxy_listen == ["0.0.0.0:8080"]
    assert s.primary_proxy_port == 8080
    assert s.mgmt_host == "0.0.0.0"
    assert s.mgmt_port == 8000
    assert s.log_blocks is True
    assert s.log_requests is True
