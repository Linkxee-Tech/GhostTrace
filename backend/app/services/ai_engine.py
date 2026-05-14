from typing import List
import os

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None


def explain_behavior(filename: str, file_type: str, suspicious_strings: List[str], iocs: dict) -> str:
    hints = []
    if file_type in {"PE executable", "ELF executable"}:
        hints.append("The sample appears to be a binary executable, which is commonly used for malware payloads.")
    if file_type == "PowerShell script":
        hints.append("The uploaded file is a PowerShell script; these are often used for living-off-the-land or fileless execution techniques.")
    if suspicious_strings:
        hints.append("Suspicious strings were detected, indicating potential network communication or command execution behavior.")
    if any(iocs.values()):
        hints.append("Indicators of compromise such as IP addresses, domains, or hashes were automatically extracted.")

    if not hints:
        hints.append("No high-confidence malicious indicators were detected, but this result should be reviewed by an analyst.")

    deterministic_summary = (
        "AI analysis summary:\n"
        f"- Filename: {filename}\n"
        f"- Detected type: {file_type}\n"
        f"- { ' '.join(hints) }\n"
        "Potential behavior may include persistence, reconnaissance, or data exfiltration depending on the payload and execution context."
    )
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or OpenAI is None:
        return deterministic_summary
    try:
        client = OpenAI(api_key=api_key)
        prompt = (
            "You are a defensive malware analyst. Provide a concise evidence-based summary.\n"
            f"Filename: {filename}\nFile type: {file_type}\n"
            f"Suspicious strings: {suspicious_strings[:20]}\n"
            f"IOCs: {iocs}\n"
            "Respond in 4-6 professional sentences."
        )
        resp = client.responses.create(model="gpt-4.1-mini", input=prompt, max_output_tokens=220)
        return (resp.output_text or "").strip() or deterministic_summary
    except Exception:
        return deterministic_summary
