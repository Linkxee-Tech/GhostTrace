from typing import Any, List

def plan_investigation(case: dict[str, Any]) -> List[str]:
    """
    Decides what tools to use and in what order based on the case data.
    """
    target_type = case.get("target_type")
    
    if target_type == "file":
        return [
            "extract_metadata",
            "scan_hashes",
            "analyze_strings",
            "build_timeline"
        ]
    elif target_type == "url":
        return [
            "analyze_url",
            "build_timeline"
        ]
    elif target_type == "log":
        return [
            "analyze_log"
        ]
    else:
        return ["extract_metadata"]
