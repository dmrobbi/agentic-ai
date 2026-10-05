"""KA-052 tests - expiry sweeper: boundary times (exact/past/future),
never-expiring grants, the exact audit-event contract, input-order
stability, non-mutation purity, tz-mix propagation, and a module
source-scan pin (no chassis import, no clock reads, no exec facilities).
No network."""
from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.auth_expiry import (
    EVENT_KIND,
    AuthGrant,
    sweep,
)

UTC = timezone.utc
BASE = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)  # arbitrary fixed clock


def test_future_expiry_stays_active():
    grant = AuthGrant("ENG-1", 1, expires_at=BASE + timedelta(hours=1))
    result = sweep([grant], BASE)
    assert result.active == (grant,)
    assert result.revoked == ()
    assert result.events == ()


def test_exact_expiry_is_revoked():
    # revokes AT expiry, not only after (KA-015: "at + after expiry")
    grant = AuthGrant("ENG-2", 2, expires_at=BASE)
    result = sweep([grant], BASE)
    assert result.active == ()
    assert result.revoked == (grant,)
    assert len(result.events) == 1


def test_past_expiry_is_revoked():
    grant = AuthGrant("ENG-3", 3, expires_at=BASE - timedelta(seconds=1))
    result = sweep([grant], BASE)
    assert result.revoked == (grant,)
    assert result.active == ()


def test_never_expiring_grant():
    grant = AuthGrant("ENG-4", 1, expires_at=None)
    result = sweep([grant], BASE + timedelta(days=3650))
    assert result.active == (grant,)
    assert result.events == ()


def test_mixed_batch_partition_and_order():
    g_past = AuthGrant("ENG-A", 1, expires_at=BASE - timedelta(minutes=5))
    g_future = AuthGrant("ENG-B", 2, expires_at=BASE + timedelta(minutes=5))
    g_forever = AuthGrant("ENG-C", 3, expires_at=None)
    g_past2 = AuthGrant("ENG-D", 1, expires_at=BASE - timedelta(hours=1))
    result = sweep([g_past, g_future, g_forever, g_past2], BASE)
    assert result.active == (g_future, g_forever)  # input order preserved
    assert result.revoked == (g_past, g_past2)     # input order preserved
    assert [e["engagement_id"] for e in result.events] == ["ENG-A", "ENG-D"]


def test_audit_event_contract_exact_shape():
    expires_at = BASE - timedelta(seconds=30)
    granted_at = BASE - timedelta(days=2)
    grant = AuthGrant("ENG-X", 3, expires_at=expires_at, granted_at=granted_at)
    result = sweep([grant], BASE)
    assert result.events[0] == {
        "event": EVENT_KIND,
        "engagement_id": "ENG-X",
        "level": 3,
        "expires_at": expires_at.isoformat(),
        "revoked_at": BASE.isoformat(),
    }


def test_empty_input():
    result = sweep([], BASE)
    assert result.active == ()
    assert result.revoked == ()
    assert result.events == ()


def test_sweep_does_not_mutate_input():
    g1 = AuthGrant("ENG-M", 1, expires_at=BASE - timedelta(days=1))
    g2 = AuthGrant("ENG-N", 2, expires_at=BASE + timedelta(days=1))
    grants = [g1, g2]
    sweep(grants, BASE)
    assert grants == [g1, g2]  # list and members untouched


def test_naive_aware_mix_propagates_typeerror():
    # documented limitation: the module does not normalize tz-ness; a
    # naive expiry against an aware `now` raises TypeError straight up
    naive_expire = datetime(2026, 10, 5, 12, 0, 0)  # naive
    grant = AuthGrant("ENG-Z", 1, expires_at=naive_expire)
    with pytest.raises(TypeError):
        sweep([grant], BASE)  # aware now


def test_module_purity_source_scan():
    # planner-purity by construction: the module never imports the chassis,
    # reads no wall clock, and uses no exec/eval facilities
    module = importlib.import_module("agentic_ai.agents.cyber.auth_expiry")
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "from agentic_ai" not in source
    assert "import agentic_ai" not in source
    assert "utcnow" not in source
    assert "time.time" not in source
    assert "subprocess" not in source
    assert "eval(" not in source
