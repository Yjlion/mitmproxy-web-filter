import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.models import DohConfig, Policy


def test_server_leading_space_stripped():
    cfg = DohConfig(server="  https://dns.nextdns.io/4f5215 ")
    assert cfg.server == "https://dns.nextdns.io/4f5215"


def test_server_stripped_via_policy_json():
    # The proxy loads policies through Policy.model_validate_json, so a stray
    # space in the file must be cleaned on load too.
    raw = '{"name":"x","doh":{"enabled":true,"server":" https://dns.nextdns.io/abc "}}'
    pol = Policy.model_validate_json(raw)
    assert pol.doh.server == "https://dns.nextdns.io/abc"


def test_clean_server_untouched():
    cfg = DohConfig(server="https://1.1.1.3/dns-query")
    assert cfg.server == "https://1.1.1.3/dns-query"
