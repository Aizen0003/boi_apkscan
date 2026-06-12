"""Tests for ml_drift.py (Plan 1.3)."""

import json

import pytest

from apkscan.scoring.ml_drift import (
    WINDOW_SIZE,
    DriftMonitor,
    _histogram,
    _psi,
)


def test_histogram_uniform():
    scores = list(range(0, 100, 1))
    hist = _histogram(scores)
    assert len(hist) == 10
    assert abs(sum(hist) - 1.0) < 1e-9


def test_histogram_empty():
    hist = _histogram([])
    assert len(hist) == 10
    assert abs(sum(hist) - 1.0) < 1e-9


def test_psi_identical_distributions():
    dist = [0.1] * 10
    psi = _psi(dist, dist)
    assert abs(psi) < 1e-9


def test_psi_shifted_distributions():
    ref = [0.4, 0.3, 0.1, 0.05, 0.05, 0.02, 0.02, 0.02, 0.02, 0.02]
    shifted = [0.02, 0.02, 0.02, 0.02, 0.02, 0.05, 0.05, 0.1, 0.3, 0.4]
    psi = _psi(ref, shifted)
    assert psi > 0.0


def test_monitor_record_and_snapshot(tmp_path):
    state_path = str(tmp_path / "drift.json")
    monitor = DriftMonitor(state_path=state_path)

    # Set reference distribution
    monitor.set_reference([50.0] * 100)

    # Record WINDOW_SIZE predictions
    snapshots = []
    for i in range(WINDOW_SIZE):
        snap = monitor.record(ml_score=50.0, rule_score=50.0)
        if snap is not None:
            snapshots.append(snap)

    assert len(snapshots) == 1
    assert snapshots[0].psi < 0.01  # similar distribution
    assert snapshots[0].alert == ""


def test_monitor_detects_drift(tmp_path):
    state_path = str(tmp_path / "drift.json")
    monitor = DriftMonitor(state_path=state_path)

    # Reference: all low scores
    monitor.set_reference([10.0] * 100)

    # Current: all high scores (major drift)
    for i in range(WINDOW_SIZE):
        snap = monitor.record(ml_score=90.0, rule_score=50.0)

    assert snap is not None
    assert snap.psi > 0.15
    assert snap.alert in ("warn", "critical")


def test_monitor_persistence(tmp_path):
    state_path = str(tmp_path / "drift.json")
    monitor = DriftMonitor(state_path=state_path)
    monitor.set_reference([50.0] * 100)

    for i in range(50):
        monitor.record(ml_score=50.0, rule_score=50.0)

    # Reload from disk
    monitor2 = DriftMonitor(state_path=state_path)
    status = monitor2.get_status()
    assert status["total_predictions"] == 50
    assert status["has_reference"] is True


def test_monitor_get_status(tmp_path):
    state_path = str(tmp_path / "drift.json")
    monitor = DriftMonitor(state_path=state_path)
    status = monitor.get_status()
    assert "total_predictions" in status
    assert "window_progress" in status
    assert "has_reference" in status


def test_monitor_divergence_detection(tmp_path):
    state_path = str(tmp_path / "drift.json")
    monitor = DriftMonitor(state_path=state_path)
    monitor.set_reference([50.0] * 100)

    # ML and rule scores diverge by >30 for all predictions
    for i in range(WINDOW_SIZE):
        snap = monitor.record(ml_score=80.0, rule_score=10.0)

    assert snap is not None
    assert snap.divergence_rate > 0.9
    assert snap.alert != ""
