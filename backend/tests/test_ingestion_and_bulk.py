import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models import Base, engine, SessionLocal
from app.models import EmailRecord, CaseRecord, BlockRecord
import os
import tempfile
import zipfile
import json
import uuid

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Clear tables
    db.query(EmailRecord).delete()
    db.query(CaseRecord).delete()
    db.query(BlockRecord).delete()
    db.commit()
    yield db
    db.close()

# Sample EMLs
SAMPLE_EML_1 = b"Message-ID: <test1@domain.com>\nFrom: a@a.com\nTo: b@b.com\nSubject: Test 1\n\nHello"
SAMPLE_EML_2 = b"Message-ID: <test2@domain.com>\nFrom: c@c.com\nTo: d@d.com\nSubject: Test 2\n\nWorld"
SAMPLE_NO_MSGID = b"From: x@x.com\nTo: y@y.com\nSubject: No ID\n\nMissing"
SAMPLE_MALICIOUS = b"Message-ID: <mal1@domain.com>\nFrom: bad@evil.com\nTo: ceo@company.com\nSubject: URGENT WIRE TRANSFER\n\nPlease send money to http://evil.com/login"

def test_idempotent_single_email_same_msgid():
    r1 = client.post("/api/analyze-file", files={"file": ("t1.eml", SAMPLE_EML_1, "message/rfc822")})
    assert r1.status_code == 200
    aid1 = r1.json()["analysis_id"]

    r2 = client.post("/api/analyze-file", files={"file": ("t1_dup.eml", SAMPLE_EML_1, "message/rfc822")})
    assert r2.status_code == 200
    aid2 = r2.json()["analysis_id"]
    
    assert aid1 == aid2

def test_idempotent_raw_email_no_msgid():
    r1 = client.post("/api/analyze-file", files={"file": ("nomsg.eml", SAMPLE_NO_MSGID, "message/rfc822")})
    aid1 = r1.json()["analysis_id"]

    r2 = client.post("/api/analyze-file", files={"file": ("nomsg_dup.eml", SAMPLE_NO_MSGID, "message/rfc822")})
    aid2 = r2.json()["analysis_id"]
    
    assert aid1 == aid2

def test_different_msgids_produce_separate_analyses():
    r1 = client.post("/api/analyze-file", files={"file": ("t1.eml", SAMPLE_EML_1, "message/rfc822")})
    r2 = client.post("/api/analyze-file", files={"file": ("t2.eml", SAMPLE_EML_2, "message/rfc822")})
    assert r1.json()["analysis_id"] != r2.json()["analysis_id"]

def test_different_raw_payloads_separate_analyses():
    r1 = client.post("/api/analyze-file", files={"file": ("r1.eml", b"Subject: A", "message/rfc822")})
    r2 = client.post("/api/analyze-file", files={"file": ("r2.eml", b"Subject: B", "message/rfc822")})
    assert r1.json()["analysis_id"] != r2.json()["analysis_id"]

def test_duplicate_submission_no_second_blockchain_anchor(setup_db):
    db = setup_db
    client.post("/api/analyze-file", files={"file": ("t1.eml", SAMPLE_EML_1, "message/rfc822")})
    blocks_before = db.query(BlockRecord).count()
    client.post("/api/analyze-file", files={"file": ("t1.eml", SAMPLE_EML_1, "message/rfc822")})
    blocks_after = db.query(BlockRecord).count()
    assert blocks_before == blocks_after == 1

def test_duplicate_submission_no_second_auto_case(setup_db):
    db = setup_db
    client.post("/api/analyze-file", files={"file": ("m.eml", SAMPLE_MALICIOUS, "message/rfc822")})
    cases_before = db.query(CaseRecord).count()
    client.post("/api/analyze-file", files={"file": ("m.eml", SAMPLE_MALICIOUS, "message/rfc822")})
    cases_after = db.query(CaseRecord).count()
    assert cases_before == cases_after

def test_auth_missing_credential_rejected():
    os.environ["INGESTION_API_KEY"] = "supersecret"
    r = client.post("/api/analyze-email", json={"raw_email": "Subject: Test"})
    assert r.status_code == 401
    del os.environ["INGESTION_API_KEY"]

def test_auth_invalid_credential_rejected():
    os.environ["INGESTION_API_KEY"] = "supersecret"
    r = client.post("/api/analyze-email", json={"raw_email": "Subject: Test"}, headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 403
    del os.environ["INGESTION_API_KEY"]

def test_auth_valid_credential_accepted():
    os.environ["INGESTION_API_KEY"] = "supersecret"
    r = client.post("/api/analyze-email", json={"raw_email": "Subject: Test"}, headers={"Authorization": "Bearer supersecret"})
    assert r.status_code == 200
    del os.environ["INGESTION_API_KEY"]

def test_auth_local_demo_behavior_no_key():
    if "INGESTION_API_KEY" in os.environ:
        del os.environ["INGESTION_API_KEY"]
    r = client.post("/api/analyze-email", json={"raw_email": "Subject: Test"})
    assert r.status_code == 200

def test_escalation_above_threshold_creates_case(setup_db):
    import app.main
    app.main.AUTO_CASE_THRESHOLD = 10
    db = setup_db
    r = client.post("/api/analyze-file", files={"file": ("m.eml", SAMPLE_MALICIOUS, "message/rfc822")})
    assert r.json()["threat_score"]["overall_score"] >= 10
    assert db.query(CaseRecord).count() == 1

def test_escalation_below_threshold_no_case(setup_db):
    import app.main
    app.main.AUTO_CASE_THRESHOLD = 99
    db = setup_db
    r = client.post("/api/analyze-file", files={"file": ("ok.eml", SAMPLE_EML_1, "message/rfc822")})
    assert r.json()["threat_score"]["overall_score"] < 80
    assert db.query(CaseRecord).count() == 0

def test_escalation_duplicate_high_risk_no_extra_case(setup_db):
    import app.main
    app.main.AUTO_CASE_THRESHOLD = 10
    db = setup_db
    client.post("/api/analyze-file", files={"file": ("m.eml", SAMPLE_MALICIOUS, "message/rfc822")})
    client.post("/api/analyze-file", files={"file": ("m.eml", SAMPLE_MALICIOUS, "message/rfc822")})
    assert db.query(CaseRecord).count() == 1

def test_bulk_valid_zip_multiple_emls():
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        with zipfile.ZipFile(tf, "w") as zf:
            zf.writestr("1.eml", SAMPLE_EML_1)
            zf.writestr("2.eml", SAMPLE_EML_2)
    with open(tf.name, "rb") as f:
        r = client.post("/api/analyze-bulk", files={"file": ("test.zip", f, "application/zip")})
    os.unlink(tf.name)
    assert r.status_code == 200
    assert r.json()["summary"]["analyzed"] == 2

def test_bulk_multiple_independently_analyzed():
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        with zipfile.ZipFile(tf, "w") as zf:
            zf.writestr("1.eml", SAMPLE_EML_1)
            zf.writestr("2.eml", SAMPLE_MALICIOUS)
    with open(tf.name, "rb") as f:
        r = client.post("/api/analyze-bulk", files={"file": ("test.zip", f, "application/zip")})
    os.unlink(tf.name)
    res = r.json()["results"]
    assert res[0]["threat_level"] != res[1]["threat_level"]

def test_bulk_malformed_eml_does_not_abort_batch():
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        with zipfile.ZipFile(tf, "w") as zf:
            zf.writestr("1.eml", b"")
            zf.writestr("2.eml", SAMPLE_EML_2)
    with open(tf.name, "rb") as f:
        r = client.post("/api/analyze-bulk", files={"file": ("test.zip", f, "application/zip")})
    os.unlink(tf.name)
    assert r.status_code == 200
    assert r.json()["summary"]["total"] == 2
    assert r.json()["summary"]["analyzed"] >= 1

def test_bulk_duplicate_classified_duplicate():
    client.post("/api/analyze-file", files={"file": ("t1.eml", SAMPLE_EML_1, "message/rfc822")})
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        with zipfile.ZipFile(tf, "w") as zf:
            zf.writestr("1.eml", SAMPLE_EML_1)
    with open(tf.name, "rb") as f:
        r = client.post("/api/analyze-bulk", files={"file": ("test.zip", f, "application/zip")})
    os.unlink(tf.name)
    assert r.json()["summary"]["duplicates"] == 1
    assert r.json()["results"][0]["status"] == "DUPLICATE"

def test_bulk_summary_counts_correct():
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        with zipfile.ZipFile(tf, "w") as zf:
            zf.writestr("1.eml", SAMPLE_EML_1)
            zf.writestr("2.eml", SAMPLE_EML_1) # duplicate within zip
    with open(tf.name, "rb") as f:
        r = client.post("/api/analyze-bulk", files={"file": ("test.zip", f, "application/zip")})
    os.unlink(tf.name)
    s = r.json()["summary"]
    assert s["total"] == 2
    assert s["analyzed"] == 1
    assert s["duplicates"] == 1

def test_bulk_automatic_escalation(setup_db):
    import app.main
    app.main.AUTO_CASE_THRESHOLD = 10
    db = setup_db
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        with zipfile.ZipFile(tf, "w") as zf:
            zf.writestr("m.eml", SAMPLE_MALICIOUS)
    with open(tf.name, "rb") as f:
        r = client.post("/api/analyze-bulk", files={"file": ("test.zip", f, "application/zip")})
    os.unlink(tf.name)
    assert r.json()["summary"]["automatically_escalated_cases"] == 1
    assert db.query(CaseRecord).count() == 1

def test_bulk_oversized_archive_rejected():
    import app.main
    app.main.MAX_BULK_ARCHIVE_MB = 0
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        tf.write(b"PK\x05\x06" + b"\x00"*18)
    with open(tf.name, "rb") as f:
        r = client.post("/api/analyze-bulk", files={"file": ("test.zip", f, "application/zip")})
    os.unlink(tf.name)
    app.main.MAX_BULK_ARCHIVE_MB = 100
    assert r.status_code == 413

def test_bulk_too_many_emails_rejected():
    import app.main
    app.main.MAX_BULK_EMAILS = 1
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        with zipfile.ZipFile(tf, "w") as zf:
            zf.writestr("1.eml", SAMPLE_EML_1)
            zf.writestr("2.eml", SAMPLE_EML_2)
    with open(tf.name, "rb") as f:
        r = client.post("/api/analyze-bulk", files={"file": ("test.zip", f, "application/zip")})
    os.unlink(tf.name)
    app.main.MAX_BULK_EMAILS = 1000
    assert r.json()["summary"]["total"] == 1

def test_bulk_nested_zip_ignored():
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        with zipfile.ZipFile(tf, "w") as zf:
            zf.writestr("inner.zip", b"PK")
    with open(tf.name, "rb") as f:
        r = client.post("/api/analyze-bulk", files={"file": ("test.zip", f, "application/zip")})
    os.unlink(tf.name)
    assert r.json()["summary"]["total"] == 0

def test_bulk_path_traversal_rejected():
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        with zipfile.ZipFile(tf, "w") as zf:
            zf.writestr("../evil.eml", SAMPLE_EML_1)
    with open(tf.name, "rb") as f:
        r = client.post("/api/analyze-bulk", files={"file": ("test.zip", f, "application/zip")})
    os.unlink(tf.name)
    assert r.json()["summary"]["total"] == 0

def test_bulk_non_eml_ignored():
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        with zipfile.ZipFile(tf, "w") as zf:
            zf.writestr("readme.txt", b"hello")
    with open(tf.name, "rb") as f:
        r = client.post("/api/analyze-bulk", files={"file": ("test.zip", f, "application/zip")})
    os.unlink(tf.name)
    assert r.json()["summary"]["total"] == 0
