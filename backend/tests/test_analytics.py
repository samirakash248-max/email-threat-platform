import pytest
from app.analytics import safe_div, run_detection_evaluation
import os
import json

def test_safe_div():
    assert safe_div(5, 10) == 0.5
    assert safe_div(0, 10) == 0.0
    assert safe_div(5, 0) == 0.0
    assert safe_div(0, 0) == 0.0

def test_analytics_with_mocked_dataset(monkeypatch, tmp_path):
    # Mock the SAMPLES_DIR to point to tmp_path
    import app.analytics
    monkeypatch.setattr(app.analytics, "SAMPLES_DIR", str(tmp_path))

    # 1. Empty dataset
    labels_path = tmp_path / "labels.json"
    labels_path.write_text("[]", encoding="utf-8")
    
    res = run_detection_evaluation()
    assert res["dataset_size"] == 0
    assert res["overall"]["accuracy"] == 0.0
    assert res["confusion_matrix"]["tp"] == 0
    
    # 2. All predictions correct (1 Benign, 1 Malicious, assuming scanner detects it)
    # Actually, we shouldn't rely on the real scanner in a unit test of the logic if we want to force specific predictions.
    # We can mock `scan_email` to return specific scores based on filename.
    
    class MockAnalysis:
        def __init__(self, score, findings=None):
            self.score = score
            self.findings = findings or []
        def model_dump(self):
            return {"threat_score": {"overall_score": self.score, "findings": self.findings}}
        def dict(self):
            return self.model_dump()
            
    def mock_scan_email(raw_bytes=None, **kwargs):
        # We can use raw_bytes to pass the filename
        filename = raw_bytes.decode()
        if filename == "tp.eml":
            return MockAnalysis(100, [{"rule_id": "R1", "rule_name": "Test", "points": 100}])
        elif filename == "tn.eml":
            return MockAnalysis(0)
        elif filename == "fp.eml":
            return MockAnalysis(100)
        elif filename == "fn.eml":
            return MockAnalysis(0)
        return MockAnalysis(0)
        
    monkeypatch.setattr(app.analytics, "scan_email", mock_scan_email)
    
    # Create mock EML files
    (tmp_path / "tp.eml").write_text("tp.eml")
    (tmp_path / "tn.eml").write_text("tn.eml")
    (tmp_path / "fp.eml").write_text("fp.eml")
    (tmp_path / "fn.eml").write_text("fn.eml")
    
    # Dataset 1: Perfect predictions
    labels_path.write_text(json.dumps([
        {"filename": "tp.eml", "is_malicious": True, "categories": ["phishing"]},
        {"filename": "tn.eml", "is_malicious": False, "categories": []}
    ]))
    
    res = run_detection_evaluation()
    assert res["dataset_size"] == 2
    assert res["overall"]["accuracy"] == 1.0
    assert res["overall"]["precision"] == 1.0
    assert res["overall"]["recall"] == 1.0
    assert res["overall"]["f1"] == 1.0
    assert res["confusion_matrix"]["tp"] == 1
    assert res["confusion_matrix"]["tn"] == 1
    assert res["confusion_matrix"]["fp"] == 0
    assert res["confusion_matrix"]["fn"] == 0
    
    # Dataset 2: All predictions incorrect
    labels_path.write_text(json.dumps([
        {"filename": "fp.eml", "is_malicious": False, "categories": []},
        {"filename": "fn.eml", "is_malicious": True, "categories": ["phishing"]}
    ]))
    
    res = run_detection_evaluation()
    assert res["overall"]["accuracy"] == 0.0
    assert res["overall"]["precision"] == 0.0
    assert res["overall"]["recall"] == 0.0
    assert res["overall"]["f1"] == 0.0
    assert res["confusion_matrix"]["tp"] == 0
    assert res["confusion_matrix"]["tn"] == 0
    assert res["confusion_matrix"]["fp"] == 1
    assert res["confusion_matrix"]["fn"] == 1
    
    # Dataset 3: Zero positives (Only TNs)
    labels_path.write_text(json.dumps([
        {"filename": "tn.eml", "is_malicious": False, "categories": []}
    ]))
    res = run_detection_evaluation()
    assert res["overall"]["accuracy"] == 1.0
    assert res["overall"]["precision"] == 0.0  # safe_div(0, 0)
    assert res["overall"]["recall"] == 0.0
    assert res["confusion_matrix"]["tn"] == 1
    
    # Dataset 4: Zero negatives (Only TPs)
    labels_path.write_text(json.dumps([
        {"filename": "tp.eml", "is_malicious": True, "categories": ["phishing"]}
    ]))
    res = run_detection_evaluation()
    assert res["overall"]["accuracy"] == 1.0
    assert res["overall"]["precision"] == 1.0
    assert res["overall"]["recall"] == 1.0
    assert res["confusion_matrix"]["tp"] == 1
    
    # Check category stats
    assert res["category_performance"]["phishing"]["detected"] == 1
    assert res["category_performance"]["phishing"]["samples"] == 1
    assert res["category_performance"]["phishing"]["precision"] == 1.0
    assert res["category_performance"]["phishing"]["recall"] == 1.0
    
    # Check rule stats
    assert len(res["rule_performance"]) == 1
    assert res["rule_performance"][0]["rule_id"] == "R1"
    assert res["rule_performance"][0]["times_triggered"] == 1
    assert res["rule_performance"][0]["avg_score_contribution"] == 100.0
