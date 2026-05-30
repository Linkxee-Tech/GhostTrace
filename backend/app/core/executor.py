from typing import Any, List
from app.tools.file_tools import extract_file_artifacts, detect_file_type
from app.tools.web_analysis import check_virustotal_hash, analyze_url_basic
from app.services.yara_scanner import yara_scan_content

def run_tool(step: str, data: Any) -> dict[str, Any]:
    try:
        if step == "extract_metadata":
            if isinstance(data, dict) and "content" in data:
                return {"extract_metadata": extract_file_artifacts(data["content"])}
            return {"extract_metadata": {"error": "No content provided"}}
            
        elif step == "scan_hashes":
            # Assuming extract_metadata already got the hashes, we just do VT lookup here
            # We'd need to extract the hash from previous results, but for simplicity we compute again or pass the state
            if isinstance(data, dict) and "content" in data:
                import hashlib
                sha256 = hashlib.sha256(data["content"]).hexdigest()
                return {"scan_hashes": check_virustotal_hash(sha256)}
            return {"scan_hashes": {}}
            
        elif step == "analyze_strings":
            # Yara scan
            if isinstance(data, dict) and "content" in data:
                return {"analyze_strings": yara_scan_content(data["content"])}
            return {"analyze_strings": {}}
            
        elif step == "build_timeline":
            return {"build_timeline": "Timeline construction deferred to final report"}
            
        elif step == "analyze_url":
            if isinstance(data, dict) and "url" in data:
                from app.services.url_analyzer import analyze_url as legacy_analyze_url
                res = legacy_analyze_url(data["url"])
                return {"analyze_url": res.model_dump()}
            return {"analyze_url": {}}
            
        elif step == "analyze_log":
            if isinstance(data, dict) and "content" in data:
                from app.services.log_analyzer import analyze_log_text
                res = analyze_log_text(data["content"])
                return {"analyze_log": res.model_dump()}
            return {"analyze_log": {}}
            
        else:
            return {step: {"error": "Unknown tool"}}
            
    except Exception as e:
        return {step: {"error": str(e)}}

def execute_plan(plan: List[str], data: Any) -> dict[str, Any]:
    results = {}
    for step in plan:
        results.update(run_tool(step, data))
    return results
