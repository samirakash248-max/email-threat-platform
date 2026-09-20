import os
import json
from typing import List, Dict, Any
from app.scanner import scan_email

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "samples"))

def safe_div(n, d):
    return float(n) / d if d > 0 else 0.0

def run_detection_evaluation() -> Dict[str, Any]:
    labels_path = os.path.join(SAMPLES_DIR, "labels.json")
    if not os.path.exists(labels_path):
        return {"error": "Evaluation dataset labels not found."}
    
    with open(labels_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    
    tp = 0
    tn = 0
    fp = 0
    fn = 0
    
    rule_stats = {}
    category_stats = {}
    
    results = []
    
    for label in dataset:
        filename = label["filename"]
        actual_malicious = label["is_malicious"]
        actual_categories = label.get("categories", [])
        
        for cat in actual_categories:
            if cat not in category_stats:
                category_stats[cat] = {"samples": 0, "detected": 0, "fp": 0, "fn": 0}
            category_stats[cat]["samples"] += 1
            
        filepath = os.path.join(SAMPLES_DIR, filename)
        if not os.path.exists(filepath):
            continue
            
        with open(filepath, "rb") as f:
            raw_bytes = f.read()
            
        analysis = scan_email(raw_bytes=raw_bytes)
        
        # Pydantic dict() or model_dump()
        try:
            analysis_dict = analysis.model_dump()
        except:
            analysis_dict = analysis.dict()
            
        threat_score = analysis_dict.get("threat_score", {})
        predicted_malicious = threat_score.get("overall_score", 0) > 40
        
        # Binary confusion matrix
        if actual_malicious and predicted_malicious:
            tp += 1
            for cat in actual_categories:
                category_stats[cat]["detected"] += 1
        elif not actual_malicious and not predicted_malicious:
            tn += 1
        elif not actual_malicious and predicted_malicious:
            fp += 1
        elif actual_malicious and not predicted_malicious:
            fn += 1
            for cat in actual_categories:
                category_stats[cat]["fn"] += 1
                
        # Rule stats
        findings = threat_score.get("findings", [])
        for f in findings:
            rid = f.get("rule_id")
            if not rid:
                continue
            if rid not in rule_stats:
                rule_stats[rid] = {
                    "rule_id": rid,
                    "rule_name": f.get("rule_name", ""),
                    "times_triggered": 0,
                    "associated_cases": [],
                    "total_score_contribution": 0
                }
            rule_stats[rid]["times_triggered"] += 1
            rule_stats[rid]["total_score_contribution"] += f.get("points", 0)
            if filename not in rule_stats[rid]["associated_cases"]:
                rule_stats[rid]["associated_cases"].append(filename)
                
            # If triggered on benign, it's a false positive for the category
            if not actual_malicious:
                # Add to a pseudo category if needed, or we just track FP overall
                pass

        results.append({
            "filename": filename,
            "actual": actual_malicious,
            "predicted": predicted_malicious,
            "score": threat_score.get("overall_score", 0)
        })

    accuracy = safe_div(tp + tn, tp + tn + fp + fn)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)

    for rid, stats in rule_stats.items():
        stats["avg_score_contribution"] = safe_div(stats["total_score_contribution"], stats["times_triggered"])

    for cat, stats in category_stats.items():
        stats["precision"] = safe_div(stats["detected"], stats["detected"] + stats["fp"])
        stats["recall"] = safe_div(stats["detected"], stats["samples"])
        stats["f1"] = safe_div(2 * stats["precision"] * stats["recall"], stats["precision"] + stats["recall"])

    return {
        "dataset_size": len(dataset),
        "overall": {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1
        },
        "confusion_matrix": {
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn
        },
        "rule_performance": list(rule_stats.values()),
        "category_performance": category_stats,
        "results": results
    }
