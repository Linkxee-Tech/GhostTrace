from pathlib import Path
from typing import Any

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover
    yara = None


def yara_status() -> dict[str, Any]:
    if yara is None:
        return {"available": False, "message": "yara-python not installed or not importable."}
    return {"available": True, "message": "yara-python is installed and available."}


def yara_scan_content(content: bytes) -> dict[str, Any]:
    if yara is None:
        return {"enabled": False, "matches": [], "message": "YARA unavailable."}

    rules_dir = Path(__file__).resolve().parents[2] / "rules"
    rule_path = rules_dir / "baseline.yar"
    if not rule_path.exists():
        return {"enabled": False, "matches": [], "message": f"No YARA rules found at {rule_path}."}

    try:
        compiled = yara.compile(filepath=str(rule_path))
        matches = compiled.match(data=content)
        names = [m.rule for m in matches]
        return {"enabled": True, "matches": names, "message": "YARA scan complete."}
    except Exception as exc:
        return {"enabled": True, "matches": [], "message": f"YARA scan failed: {exc}"}
