"""Tests for ml_monitor.py (Plan 1.3)."""

from datetime import datetime, timedelta, timezone

from apkscan.schema import FeatureSet, SampleMetadata
from apkscan.scoring.ml_monitor import check_concept_drift, temporal_train_test_split


def _make_dummy_feature_set(created_at: datetime) -> FeatureSet:
    return FeatureSet(
        created_at=created_at,
        sample=SampleMetadata(
            sha256="0" * 64,
            file_name="dummy.apk",
            file_size=1000,
        ),
    )


def test_temporal_train_test_split_empty():
    train, test = temporal_train_test_split([])
    assert train == []
    assert test == []


def test_temporal_train_test_split():
    now = datetime.now(timezone.utc)
    samples = [
        _make_dummy_feature_set(now - timedelta(days=1)),
        _make_dummy_feature_set(now - timedelta(days=3)),
        _make_dummy_feature_set(now),
        _make_dummy_feature_set(now - timedelta(days=2)),
    ]

    # test_ratio = 0.25 (1 out of 4 should go to test)
    train, test = temporal_train_test_split(samples, test_ratio=0.25)
    assert len(train) == 3
    assert len(test) == 1

    # Verify they are split chronologically (train has oldest, test has newest)
    assert train[0].created_at < train[1].created_at < train[2].created_at
    assert train[2].created_at < test[0].created_at


def test_check_concept_drift_no_drift():
    # perfect accuracy (F1 = 1.0)
    preds = [1, 0, 1, 1, 0]
    labels = [1, 0, 1, 1, 0]
    drift, f1 = check_concept_drift(preds, labels)
    assert drift is False
    assert f1 == 1.0


def test_check_concept_drift_with_drift():
    # low accuracy (F1 = 0.4)
    preds = [1, 0, 0, 0, 0]
    labels = [1, 1, 1, 1, 0]
    drift, f1 = check_concept_drift(preds, labels, f1_threshold=0.85)
    assert drift is True
    assert f1 < 0.85


def test_check_concept_drift_empty_or_mismatched():
    drift, f1 = check_concept_drift([], [])
    assert drift is False
    assert f1 == 0.0

    drift, f1 = check_concept_drift([1], [1, 0])
    assert drift is False
    assert f1 == 0.0
