"""Ingestion + storage + hashing + audit tests (T0.3 / AC1, T0.16 infra)."""

from apkscan import audit
from apkscan.db.models import AuditEvent, Job, JobStatus, Sample
from apkscan.ingestion.hashing import hash_bytes, hash_file
from apkscan.ingestion.service import ingest_sample
from apkscan.storage.base import StorageError


# --- hashing ---
def test_hash_file_matches_bytes(fake_apk):
    by_file = hash_file(fake_apk)
    by_bytes = hash_bytes(fake_apk.read_bytes())
    assert by_file["sha256"] == by_bytes["sha256"]
    assert by_file["size"] == by_bytes["size"]
    assert len(by_file["sha256"]) == 64


# --- storage ---
def test_storage_roundtrip_and_traversal_guard(store, fake_apk):
    key = "samples/abc.apk"
    store.put_file(key, fake_apk)
    assert store.exists(key)
    assert store.get_bytes(key) == fake_apk.read_bytes()
    assert store.local_path(key).is_file()
    for bad in ("../escape", "/abs", "a/../../b"):
        try:
            store.put_bytes(bad, b"x")
            assert False, f"expected traversal rejection for {bad!r}"
        except StorageError:
            pass


def test_storage_put_file_is_write_once(store, fake_apk, tmp_path):
    key = "samples/x.apk"
    store.put_file(key, fake_apk)
    other = tmp_path / "other.apk"
    other.write_bytes(b"DIFFERENT")
    store.put_file(key, other)  # overwrite=False default -> no-op
    assert store.get_bytes(key) == fake_apk.read_bytes()


# --- ingestion (AC1) ---
def test_ingest_creates_sample_job_and_audit(db_session, store, fake_apk):
    result = ingest_sample(
        src_path=fake_apk, file_name="sample.apk", store=store, session=db_session, actor="analyst1"
    )
    db_session.commit()

    assert len(result.sample_sha256) == 64
    assert result.job_id
    assert result.deduped is False

    sample = db_session.get(Sample, result.sample_sha256)
    assert sample is not None
    assert sample.file_name == "sample.apk"
    assert sample.received_by == "analyst1"
    assert sample.retention_until is not None  # chain-of-custody
    assert store.exists(sample.storage_key)

    job = db_session.get(Job, result.job_id)
    assert job.status == JobStatus.QUEUED

    actions = {e.action for e in db_session.query(AuditEvent).all()}
    assert "sample.ingested" in actions
    assert "job.created" in actions


def test_duplicate_upload_dedupes_by_hash(db_session, store, fake_apk):
    first = ingest_sample(src_path=fake_apk, file_name="a.apk", store=store, session=db_session)
    db_session.commit()
    second = ingest_sample(src_path=fake_apk, file_name="a-again.apk", store=store, session=db_session)
    db_session.commit()

    assert second.sample_sha256 == first.sample_sha256
    assert second.deduped is True
    assert second.reused_job is True
    assert second.job_id == first.job_id  # reused, not a second analysis
    assert db_session.query(Sample).count() == 1
    assert db_session.query(Job).count() == 1


def test_force_reanalyze_creates_new_job(db_session, store, fake_apk):
    first = ingest_sample(src_path=fake_apk, file_name="a.apk", store=store, session=db_session)
    db_session.commit()
    second = ingest_sample(
        src_path=fake_apk, file_name="a.apk", store=store, session=db_session, force_reanalyze=True
    )
    db_session.commit()
    assert second.job_id != first.job_id
    assert db_session.query(Job).count() == 2
    assert db_session.query(Sample).count() == 1  # still one sample


# --- audit chain (T0.16) ---
def test_audit_chain_is_intact_and_tamper_evident(db_session, store, fake_apk):
    ingest_sample(src_path=fake_apk, file_name="a.apk", store=store, session=db_session)
    db_session.commit()
    assert audit.verify_chain(db_session) == []

    # Tamper with an event's detail without recomputing the hash.
    ev = db_session.query(AuditEvent).first()
    ev.detail = {"tampered": True}
    db_session.commit()
    assert ev.id in audit.verify_chain(db_session)
