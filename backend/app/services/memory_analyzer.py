from typing import Any

try:
    from volatility3.framework import constants  # type: ignore
except Exception:  # pragma: no cover
    constants = None


def volatility_status() -> dict[str, Any]:
    if constants is None:
        return {
            "available": False,
            "message": "volatility3 not installed or not importable.",
        }
    return {
        "available": True,
        "message": "volatility3 is installed and available for defensive memory forensics.",
        "version": getattr(constants, "PACKAGE_VERSION", "unknown"),
    }
