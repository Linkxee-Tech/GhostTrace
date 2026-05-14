from typing import List
import os
import time

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None

def _openai_generate_text(client, model: str, prompt: str, max_tokens: int = 220) -> str:
    if hasattr(client, "responses"):
        resp = client.responses.create(model=model, input=prompt, max_output_tokens=max_tokens)
        return (getattr(resp, "output_text", "") or "").strip()
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
    )
    return ((resp.choices[0].message.content if resp and resp.choices else "") or "").strip()


def _is_rate_limited(exc: Exception) -> bool:
    name = type(exc).__name__.lower()
    if "ratelimit" in name:
        return True
    status = getattr(exc, "status_code", None)
    if status == 429:
        return True
    return "429" in str(exc)


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
        models = [os.getenv("OPENAI_MODEL", "").strip() or "gpt-4.1-mini", "gpt-4o-mini"]
        seen = set()
        for model in models:
            if model in seen:
                continue
            seen.add(model)
            for attempt in range(3):
                try:
                    text = _openai_generate_text(client, model, prompt, max_tokens=220)
                    if text:
                        return text
                except Exception as exc:
                    if _is_rate_limited(exc) and attempt < 2:
                        time.sleep(1.2 * (attempt + 1))
                        continue
                    break
        return deterministic_summary
    except Exception:
        return deterministic_summary
