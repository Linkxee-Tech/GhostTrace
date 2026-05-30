import uuid
from typing import Any, Dict
from app.core.planner import plan_investigation
from app.core.executor import execute_plan
from app.core.validator import validate_results
from app.schemas import InvestigationResult # Will rename this in schemas.py
from app.services.ai_engine import explain_behavior

def format_final(case: Dict[str, Any], validated: Dict[str, Any]) -> dict:
    """
    Formats the validated results into the InvestigationResult schema.
    """
    scan_id = str(uuid.uuid4())
    target_type = case.get("target_type", "unknown")
    target_value = case.get("target_value", "unknown")
    
    # Calculate score & severity based on validated data
    score = 0
    severity = "low"
    
    meta = validated.get("extract_metadata", {})
    if target_type == "file" and meta and "error" not in meta:
        if meta.get("entropy", 0) > 7.0:
            score += 20
        if len(meta.get("suspicious_strings", [])) > 0:
            score += 10
            
    vt = validated.get("scan_hashes", {})
    if vt.get("malicious", 0) > 0:
        score += 40
        
    yara = validated.get("analyze_strings", {})
    if yara.get("matches", []):
        score += 30
        
    ai_explanation = ""
    iocs = [{"type": "yara", "value": m} for m in yara.get("matches", [])]
    
    # Delegate to legacy outputs if present to preserve functionality
    if "analyze_url" in validated and "risk_score" in validated["analyze_url"]:
        legacy = validated["analyze_url"]
        score = legacy.get("risk_score", 0)
        severity = legacy.get("severity", "low")
        ai_explanation = legacy.get("ai_explanation", legacy.get("summary", ""))
        iocs = legacy.get("iocs", [])
    elif "analyze_log" in validated and "risk_score" in validated["analyze_log"]:
        legacy = validated["analyze_log"]
        score = legacy.get("risk_score", 0)
        severity = legacy.get("severity", "low")
        ai_explanation = legacy.get("ai_explanation", legacy.get("summary", ""))
        iocs = legacy.get("iocs", [])
    else:
        score = min(100, score)
        if score >= 80:
            severity = "critical"
        elif score >= 60:
            severity = "high"
        elif score >= 30:
            severity = "medium"
        else:
            severity = "low"
        ai_explanation = explain_behavior(target_value, target_type, meta.get("suspicious_strings", []), yara.get("matches", []))
    
    evidence = []
    for step, data in validated.items():
        if step != "validation_flags" and step != "confidence_penalty":
            evidence.append({"tool": step, "data": data})

    confidence = 100 - validated.get("confidence_penalty", 0)
    if "validation_flags" in validated and len(validated["validation_flags"]) > 0:
        confidence -= 10
        
    result = {
        "scan_id": scan_id,
        "target_type": target_type,
        "target_value": target_value,
        "risk_score": score,
        "severity": severity,
        "summary": ai_explanation[:200] + "..." if len(ai_explanation) > 200 else ai_explanation,
        "iocs": iocs,
        "timeline": [{"stage": "Analysis", "details": "Automated pipeline execution completed"}],
        "evidence": evidence,
        "ai_explanation": ai_explanation,
        "recommendation": "Quarantine the target and investigate related activity." if severity in ["high", "critical"] else "Continue monitoring.",
        "confidence": max(0, confidence),
        "metadata": {"validation_flags": validated.get("validation_flags", [])},
        "execution_log": [{"action": "run_investigation", "status": "completed"}]
    }
    return result

def run_investigation(case: Dict[str, Any]) -> dict:
    """
    Main entry point for the investigation pipeline.
    """
    plan = plan_investigation(case)
    raw_results = execute_plan(plan, case)
    validated = validate_results(raw_results)

    return format_final(case, validated)
