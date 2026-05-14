import re
from typing import Any

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")
URL_REGEX = re.compile(r"https?://[^\s'\"]+")
HASH_REGEX = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def extract_iocs(content: bytes) -> dict[str, list[str]]:
    text = content.decode("utf-8", errors="ignore")
    ips = sorted(set(match.group(0) for match in IP_REGEX.finditer(text)))
    urls = sorted(set(match.group(0) for match in URL_REGEX.finditer(text)))
    domains = sorted({match.group(0) for match in DOMAIN_REGEX.finditer(text) if not match.group(0).startswith("http")})
    hashes = sorted(set(match.group(0) for match in HASH_REGEX.finditer(text) if len(match.group(0)) in (32, 40, 64)))

    registry_keys = sorted(set(match.group(0) for match in re.finditer(r"HKEY_[A-Z_\\]+\\[A-Za-z0-9_\\]+", text)))
    suspicious_commands = sorted(set(match.group(0) for match in re.finditer(r"(?:powershell|cmd\.exe|bash|sh)[^\r\n]*", text, flags=re.IGNORECASE)))

    return {
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "hashes": hashes,
        "registry_keys": registry_keys,
        "suspicious_commands": suspicious_commands,
    }
