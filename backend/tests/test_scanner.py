import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.scanner import scan_email

client = TestClient(app)
SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "samples"))

def read_sample(filename: str) -> bytes:
    with open(os.path.join(SAMPLES_DIR, filename), "rb") as f:
        return f.read()

# ----------------------------------------------------
# Scanner Heuristic & Forensics Tests
# ----------------------------------------------------

def test_legitimate_email():
    res = scan_email(raw_bytes=read_sample("01_legitimate_newsletter.eml"))
    assert res.authentication.spf.status == "pass"
    assert res.authentication.dkim.status == "pass"
    assert res.authentication.dmarc.status == "pass"
    assert res.threat_score.overall_score == 0
    assert res.threat_score.risk_level == "Low"

def test_phishing_account_suspension():
    res = scan_email(raw_bytes=read_sample("02_phishing_account_suspension.eml"))
    assert res.threat_score.overall_score >= 80
    assert res.threat_score.risk_level == "Critical"
    rule_ids = [f.rule_id for f in res.detection_findings]
    assert "RULE-01" in rule_ids
    assert "RULE-02" in rule_ids

def test_ceo_fraud():
    res = scan_email(raw_bytes=read_sample("03_spoofed_sender_ceo_fraud.eml"))
    rule_ids = [f.rule_id for f in res.detection_findings]
    assert "RULE-03" in rule_ids
    assert res.threat_score.overall_score >= 60

def test_reply_to_mismatch():
    res = scan_email(raw_bytes=read_sample("04_reply_to_mismatch.eml"))
    rule_ids = [f.rule_id for f in res.detection_findings]
    assert "RULE-04" in rule_ids
    assert res.threat_score.overall_score >= 30

def test_auth_failures():
    res = scan_email(raw_bytes=read_sample("05_spf_dkim_dmarc_fail.eml"))
    assert res.authentication.dmarc.status == "fail"
    rule_ids = [f.rule_id for f in res.detection_findings]
    assert "RULE-05" in rule_ids
    assert res.threat_score.risk_level == "Critical"

def test_suspicious_url():
    res = scan_email(raw_bytes=read_sample("06_suspicious_url_ip_mismatch.eml"))
    rule_ids = [f.rule_id for f in res.detection_findings]
    assert "RULE-07" in rule_ids
    assert "RULE-08" in rule_ids
    assert res.threat_score.risk_level == "Critical"

def test_multi_hop_relays():
    res = scan_email(raw_bytes=read_sample("07_multi_hop_relays.eml"))
    assert len(res.relays) == 4
    assert res.relays[0].role == "probable originating infrastructure"

def test_dangerous_attachments():
    res = scan_email(raw_bytes=read_sample("08_dangerous_attachment_malware.eml"))
    rule_ids = [f.rule_id for f in res.detection_findings]
    assert "RULE-09" in rule_ids
    assert res.threat_score.risk_level == "Critical"

def test_missing_headers():
    res = scan_email(raw_bytes=read_sample("09_missing_headers.eml"))
    rule_ids = [f.rule_id for f in res.detection_findings]
    assert "RULE-11" in rule_ids

def test_malformed_email():
    res = scan_email(raw_bytes=read_sample("10_malformed_email.eml"))
    assert res.metadata is not None

# ----------------------------------------------------
# API Endpoint Tests
# ----------------------------------------------------

def test_api_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"

def test_api_samples():
    r = client.get("/api/sample-emails")
    assert r.status_code == 200
    assert len(r.json()) == 10

def test_api_analyze_json():
    with open(os.path.join(SAMPLES_DIR, "01_legitimate_newsletter.eml"), "r", encoding="utf-8") as f:
        r = client.post("/api/analyze-email", json={"raw_email": f.read()})
    assert r.status_code == 200
    assert r.json()["threat_score"]["overall_score"] == 0

def test_api_analyze_file():
    with open(os.path.join(SAMPLES_DIR, "08_dangerous_attachment_malware.eml"), "rb") as f:
        r = client.post("/api/analyze-file", files={"file": ("malware.eml", f, "message/rfc822")})
    assert r.status_code == 200
    assert len(r.json()["attachments"]) >= 1

def test_api_cases():
    with open(os.path.join(SAMPLES_DIR, "02_phishing_account_suspension.eml"), "r", encoding="utf-8") as f:
        scan_r = client.post("/api/analyze-email", json={"raw_email": f.read()})
    aid = scan_r.json()["analysis_id"]

    case_r = client.post("/api/cases", json={"title": "Test Incident", "priority": "HIGH", "initial_analysis_id": aid})
    assert case_r.status_code == 200
    cid = case_r.json()["id"]

    note_r = client.post(f"/api/cases/{cid}/notes", json={"content": "Blocked sender domain."})
    assert note_r.status_code == 200

def test_api_stats():
    r = client.get("/api/dashboard/stats")
    assert r.status_code == 200
    assert "total_analyzed_emails" in r.json()

def test_api_demo_seed_and_reset():
    r = client.post("/api/demo/reset")
    assert r.status_code == 200
    assert r.json()["status"] == "success"
