from typing import Any, Dict

def validate_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Checks for missing evidence, contradictions, and flags uncertainty.
    """
    cleaned_results = results.copy()
    validation_flags = []
    
    # 1. Check for missing evidence
    if "extract_metadata" not in cleaned_results or "error" in cleaned_results.get("extract_metadata", {}):
        validation_flags.append("Missing core file metadata.")
        
    # 2. Check for contradictions
    # E.g. YARA says malicious, VT says benign
    yara_matches = cleaned_results.get("analyze_strings", {}).get("matches", [])
    vt_stats = cleaned_results.get("scan_hashes", {})
    
    is_vt_malicious = vt_stats.get("malicious", 0) > 0
    is_yara_malicious = len(yara_matches) > 0
    
    if is_yara_malicious and not is_vt_malicious:
        validation_flags.append("Contradiction: YARA matched signatures but VirusTotal found 0 malicious hits. Flagging as suspicious.")
        cleaned_results["confidence_penalty"] = 10
        
    # 3. Flag uncertainty
    if not vt_stats.get("available"):
        validation_flags.append("Uncertainty: Threat intelligence (VirusTotal) was unavailable.")
        
    cleaned_results["validation_flags"] = validation_flags
    return cleaned_results
