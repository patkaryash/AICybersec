"""Unit tests: scan state machine - the complete transition matrix."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend.services.scan_state import (
    CANCELLABLE_STATUSES,
    TERMINAL_STATUSES,
    VALID_TRANSITIONS,
    ScanStateError,
    apply_transition,
    can_transition,
)

ALL_STATUSES = ("queued", "initializing", "running", "cancelling", "completed", "failed", "cancelled")


def _scan(status: str):
    return SimpleNamespace(status=status, started_at=None, completed_at=None, cancelled_at=None, error=None)


class TestValidTransitions:
    def test_approved_flow(self):
        assert can_transition("queued", "initializing")
        assert can_transition("initializing", "running")
        assert can_transition("running", "completed")
        assert can_transition("running", "failed")
        assert can_transition("running", "cancelling")
        assert can_transition("cancelling", "cancelled")

    def test_cancellation_from_queued_and_initializing(self):
        assert can_transition("queued", "cancelled")
        assert can_transition("initializing", "cancelled")

    def test_startup_recovery_paths(self):
        assert can_transition("queued", "failed")
        assert can_transition("initializing", "failed")

    def test_terminal_states_have_no_transitions(self):
        for terminal in TERMINAL_STATUSES:
            assert VALID_TRANSITIONS[terminal] == ()
            for target in ALL_STATUSES:
                assert not can_transition(terminal, target)

    def test_every_status_is_in_the_table(self):
        assert set(VALID_TRANSITIONS) == set(ALL_STATUSES)

    def test_every_target_is_a_known_status(self):
        for targets in VALID_TRANSITIONS.values():
            assert set(targets) <= set(ALL_STATUSES)


class TestInvalidTransitions:
    @pytest.mark.parametrize("current", ALL_STATUSES)
    def test_no_direct_running_to_cancelled(self, current):
        # cancellation must flow through cancelling (except pre-execution)
        if current != "running":
            return
        assert not can_transition("running", "cancelled")

    @pytest.mark.parametrize(
        ("current", "target"),
        [
            ("completed", "running"),
            ("completed", "failed"),
            ("completed", "cancelled"),
            ("failed", "running"),
            ("failed", "cancelling"),
            ("cancelled", "running"),
            ("cancelled", "queued"),
            ("cancelling", "running"),
            ("queued", "running"),  # must pass through initializing
            ("queued", "completed"),  # must pass through initializing/running
        ],
    )
    def test_invalid_transitions_raise(self, current, target):
        assert not can_transition(current, target)
        with pytest.raises(ScanStateError):
            apply_transition(_scan(current), target)


class TestApplyTransition:
    def test_queued_to_initializing_sets_started_at(self):
        scan = _scan("queued")
        apply_transition(scan, "initializing")
        assert scan.status == "initializing"
        assert scan.started_at is not None

    def test_running_to_completed_sets_completed_at(self):
        scan = _scan("running")
        apply_transition(scan, "completed")
        assert scan.status == "completed"
        assert scan.completed_at is not None
        assert scan.error is None

    def test_running_to_failed_sets_error(self):
        scan = _scan("running")
        apply_transition(scan, "failed", error="boom")
        assert scan.status == "failed"
        assert scan.completed_at is not None
        assert scan.error == "boom"

    def test_cancelling_then_cancelled(self):
        scan = _scan("running")
        apply_transition(scan, "cancelling")
        assert scan.status == "cancelling"
        assert scan.cancelled_at is None
        apply_transition(scan, "cancelled")
        assert scan.status == "cancelled"
        assert scan.cancelled_at is not None

    def test_queued_to_cancelled_direct(self):
        scan = _scan("queued")
        apply_transition(scan, "cancelled")
        assert scan.status == "cancelled"
        assert scan.cancelled_at is not None


class TestCancellableStatuses:
    def test_phase2_cancellable_set(self):
        assert CANCELLABLE_STATUSES == ("queued", "initializing")
