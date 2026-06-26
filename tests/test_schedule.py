import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import datetime as _dt_module
import pytest
from unittest.mock import patch
from shared.models import Policy, ScheduleConfig, TimeWindow

# Keep a reference to the real datetime class before any patching so _now()
# still works when called inside a `with patch("datetime.datetime"):` block.
_real_dt = _dt_module.datetime


def _now(weekday, hour, minute):
    """Real datetime for weekday 0=Mon … 6=Sun, 2024-01-01 is a Monday."""
    return _real_dt(2024, 1, 1 + weekday, hour, minute)


def _policy(windows, enabled=True):
    cfg = ScheduleConfig(enabled=enabled, active_windows=[TimeWindow(**w) for w in windows])
    p = Policy(name="test")
    p.schedule = cfg
    return p


class TestScheduleIsActiveNow:
    def test_disabled_always_active(self):
        p = _policy([], enabled=False)
        assert p.schedule.is_active_now() is True

    def test_no_windows_while_enabled_is_active(self):
        # enabled=True but no windows → fail-open → still active
        p = _policy([], enabled=True)
        assert p.schedule.is_active_now() is True

    def test_within_window(self):
        p = _policy([{"days": [0], "start": "09:00", "end": "17:00"}])
        with patch("datetime.datetime") as m:
            m.now.return_value = _now(0, 12, 0)
            assert p.schedule.is_active_now() is True

    def test_before_window(self):
        p = _policy([{"days": [0], "start": "09:00", "end": "17:00"}])
        with patch("datetime.datetime") as m:
            m.now.return_value = _now(0, 8, 59)
            assert p.schedule.is_active_now() is False

    def test_after_window(self):
        p = _policy([{"days": [0], "start": "09:00", "end": "17:00"}])
        with patch("datetime.datetime") as m:
            m.now.return_value = _now(0, 17, 1)
            assert p.schedule.is_active_now() is False

    def test_wrong_day(self):
        p = _policy([{"days": [1], "start": "09:00", "end": "17:00"}])  # Tuesday only
        with patch("datetime.datetime") as m:
            m.now.return_value = _now(0, 12, 0)  # Monday
            assert p.schedule.is_active_now() is False

    def test_boundary_start(self):
        p = _policy([{"days": [0], "start": "09:00", "end": "17:00"}])
        with patch("datetime.datetime") as m:
            m.now.return_value = _now(0, 9, 0)
            assert p.schedule.is_active_now() is True

    def test_boundary_end(self):
        p = _policy([{"days": [0], "start": "09:00", "end": "17:00"}])
        with patch("datetime.datetime") as m:
            m.now.return_value = _now(0, 17, 0)
            assert p.schedule.is_active_now() is True

    def test_multiple_windows_second_matches(self):
        p = _policy([
            {"days": [0], "start": "08:00", "end": "12:00"},
            {"days": [0], "start": "14:00", "end": "18:00"},
        ])
        with patch("datetime.datetime") as m:
            m.now.return_value = _now(0, 15, 0)
            assert p.schedule.is_active_now() is True

    def test_gap_between_windows_inactive(self):
        p = _policy([
            {"days": [0], "start": "08:00", "end": "12:00"},
            {"days": [0], "start": "14:00", "end": "18:00"},
        ])
        with patch("datetime.datetime") as m:
            m.now.return_value = _now(0, 13, 0)  # midday gap
            assert p.schedule.is_active_now() is False

    def test_overnight_via_two_windows(self):
        # Evening 21:00–23:59 + early morning 00:00–07:00 cover the night.
        p = _policy([
            {"days": list(range(7)), "start": "21:00", "end": "23:59"},
            {"days": list(range(7)), "start": "00:00", "end": "07:00"},
        ])
        for h, expected in [(22, True), (3, True), (8, False)]:
            with patch("datetime.datetime") as m:
                m.now.return_value = _now(0, h, 30)
                assert p.schedule.is_active_now() is expected, f"hour={h}"


class TestTimeWindowValidation:
    def test_valid_time(self):
        w = TimeWindow(start="09:00", end="17:30")
        assert w.start == "09:00"
        assert w.end == "17:30"

    def test_invalid_time_format(self):
        with pytest.raises(Exception):
            TimeWindow(start="9am", end="5pm")

    def test_invalid_hours(self):
        with pytest.raises(Exception):
            TimeWindow(start="25:00", end="17:00")

    def test_days_normalized_mod7(self):
        w = TimeWindow(days=[0, 1, 8])  # 8 % 7 = 1
        assert 1 in w.days

    def test_default_days_all_week(self):
        w = TimeWindow()
        assert set(w.days) == set(range(7))


class TestGetPolicySchedule:
    """Verify that policy_router.get_policy respects schedules."""

    def setup_method(self):
        import proxy.addons.policy_router as pr
        self._orig = pr._policies[:]
        pr._policies = []

    def teardown_method(self):
        import proxy.addons.policy_router as pr
        pr._policies = self._orig

    def test_inactive_policy_not_returned(self):
        from proxy.addons.policy_router import get_policy
        import proxy.addons.policy_router as pr

        p = Policy(name="strict", source_ips=["10.0.0.1"])
        p.schedule = ScheduleConfig(
            enabled=True,
            active_windows=[TimeWindow(days=[0], start="09:00", end="17:00")]
        )
        pr._policies = [p]

        with patch("datetime.datetime") as m:
            m.now.return_value = _now(0, 20, 0)  # outside window
            assert get_policy("10.0.0.1") is None

    def test_active_policy_returned(self):
        from proxy.addons.policy_router import get_policy
        import proxy.addons.policy_router as pr

        p = Policy(name="strict", source_ips=["10.0.0.1"])
        p.schedule = ScheduleConfig(
            enabled=True,
            active_windows=[TimeWindow(days=[0], start="09:00", end="17:00")]
        )
        pr._policies = [p]

        with patch("datetime.datetime") as m:
            m.now.return_value = _now(0, 12, 0)
            assert get_policy("10.0.0.1") is p

    def test_inactive_specific_falls_through_to_catchall(self):
        """A scheduled-off specific-IP policy lets the catch-all take over."""
        from proxy.addons.policy_router import get_policy
        import proxy.addons.policy_router as pr

        strict = Policy(name="strict", source_ips=["10.0.0.1"])
        strict.schedule = ScheduleConfig(
            enabled=True,
            active_windows=[TimeWindow(days=[0], start="09:00", end="17:00")]
        )
        catchall = Policy(name="default", source_ips=[])
        pr._policies = [strict, catchall]

        with patch("datetime.datetime") as m:
            m.now.return_value = _now(0, 20, 0)  # strict is off
            assert get_policy("10.0.0.1") is catchall

    def test_cidr_policy_skipped_when_inactive(self):
        from proxy.addons.policy_router import get_policy
        import proxy.addons.policy_router as pr

        cidr_p = Policy(name="cidr", source_ips=["10.0.0.0/24"])
        cidr_p.schedule = ScheduleConfig(
            enabled=True,
            active_windows=[TimeWindow(days=[0], start="09:00", end="17:00")]
        )
        pr._policies = [cidr_p]

        with patch("datetime.datetime") as m:
            m.now.return_value = _now(0, 20, 0)
            assert get_policy("10.0.0.5") is None
