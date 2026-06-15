import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

dns_message = pytest.importorskip("dns.message")
import dns.message
import dns.rrset
import dns.rcode

import dns.edns
from proxy.addons.doh_filter import _classify, _should_filter
from shared.models import DohConfig


def _resp(name, rdtype="A", rcode=None, records=None, ttl=60):
    q = dns.message.make_query(name, rdtype)
    msg = dns.message.make_response(q)
    if rcode is not None:
        msg.set_rcode(rcode)
    for data in (records or []):
        msg.answer.append(dns.rrset.from_text(f"{name}.", ttl, "IN", rdtype, data))
    return msg


class TestClassify:
    def test_sinkhole_zero_ip_blocks(self):
        # NextDNS / filtering resolvers return 0.0.0.0 for blocked names.
        blocked, detail, ttl = _classify([_resp("ads.example.com", "A", records=["0.0.0.0"])])
        assert blocked
        assert "0.0.0.0" in detail

    def test_sinkhole_ipv6_blocks(self):
        blocked, _, _ = _classify([_resp("ads.example.com", "AAAA", records=["::"])])
        assert blocked

    def test_nxdomain_blocks(self):
        blocked, detail, _ = _classify([_resp("gone.example.com", "A", rcode=dns.rcode.NXDOMAIN)])
        assert blocked
        assert detail == "NXDOMAIN"

    def test_normal_answer_allowed(self):
        blocked, detail, _ = _classify([_resp("good.example.com", "A", records=["93.184.216.34"])])
        assert not blocked
        assert detail == ""

    def test_noerror_empty_answer_allowed(self):
        # e.g. AAAA query for an IPv4-only host: NOERROR, no records -> NOT blocked.
        blocked, _, _ = _classify([_resp("ipv4only.example.com", "AAAA", records=[])])
        assert not blocked

    def test_mixed_one_sinkhole_blocks(self):
        msgs = [
            _resp("x.example.com", "A", records=["0.0.0.0"]),
            _resp("x.example.com", "AAAA", records=[]),
        ]
        assert _classify(msgs)[0]

    def test_loopback_sinkhole_blocks(self):
        assert _classify([_resp("x.com", "A", records=["127.0.0.1"])])[0]

    def test_adguard_block_page_ip_blocks(self):
        # AdGuard Family redirects blocked adult domains to a block-page IP
        # (not a sinkhole) — must still be detected.
        blocked, detail, _ = _classify([_resp("adult.example.com", "A", records=["94.140.14.35"])])
        assert blocked
        assert "94.140.14.35" in detail

    def test_real_ip_allowed(self):
        # AdGuard Default returns the real IP for adult sites it doesn't filter.
        assert not _classify([_resp("pornhub.com", "A", records=["66.254.114.41"])])[0]

    def test_ede_filtered_blocks(self):
        # NextDNS / Cloudflare attach an EDE option (RFC 8914) on blocked names,
        # even with no sinkhole IP in the answer.
        msg = _resp("blocked.example.com", "A", records=[])
        msg.use_edns(0, options=[dns.edns.EDEOption(17, "Blocked by policy")])
        blocked, detail, _ = _classify([msg])
        assert blocked
        assert "EDE 17" in detail


class TestShouldFilter:
    def test_exclude(self):
        cfg = DohConfig(enabled=True, exclude=["school.edu"])
        assert not _should_filter("school.edu", cfg)
        assert not _should_filter("sub.school.edu", cfg)
        assert _should_filter("other.com", cfg)

    def test_include_only(self):
        cfg = DohConfig(enabled=True, include_only=["watch.me"])
        assert _should_filter("watch.me", cfg)
        assert not _should_filter("elsewhere.com", cfg)
