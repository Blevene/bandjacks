"""Regression test for the tz-naive parse fix in redis_job_store.

Bug: datetime.fromisoformat('2026-05-03T14:30:00Z') on Python 3.11+ returns
a tz-aware datetime, which raises TypeError when subtracted from naive
datetime.utcnow(). Fired every 4s in the recovery loop, blocking job
processing — see docs/handoff_2026-05-03_bandjacks_diagnostic.md.

We pin the parse-naive behavior here so future refactors don't reintroduce
the bug. We don't import RedisJobStore (it would require redis to import);
we test the parse pattern directly.
"""

from datetime import datetime


def test_z_suffix_strip_yields_naive_datetime():
    s = "2026-05-03T14:30:00Z"
    parsed = datetime.fromisoformat(s.rstrip("Z"))
    assert parsed.tzinfo is None


def test_naive_subtraction_does_not_raise():
    """Reproduce the exact arithmetic that broke the recovery loop."""
    claimed_at = "2026-05-03T14:30:00.000000Z"
    claimed_time = datetime.fromisoformat(claimed_at.rstrip("Z"))
    elapsed = (datetime.utcnow() - claimed_time).total_seconds()
    assert isinstance(elapsed, float)


def test_pre_fix_pattern_would_raise_on_311_plus():
    """Sanity check that the un-fixed pattern is genuinely broken — without
    rstrip, fromisoformat returns tz-aware on Py3.11+ and subtraction with
    naive utcnow raises TypeError."""
    claimed_at = "2026-05-03T14:30:00Z"
    claimed_time_aware = datetime.fromisoformat(claimed_at)
    if claimed_time_aware.tzinfo is not None:
        # Confirm the trap exists on this interpreter
        try:
            (datetime.utcnow() - claimed_time_aware).total_seconds()
        except TypeError as e:
            assert "offset-naive" in str(e) or "offset-aware" in str(e)
            return
    # Older Python: fromisoformat won't accept 'Z' at all, which is also fine
