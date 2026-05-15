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


def explain_behavior(target: str, type: str, findings: list[str], iocs: dict) -> str:
    # This function now acts as a high-level investigator
    api_key = os.getenv("OPENAI_API_KEY")
    deterministic_summary = (
        f"Forensic investigation of {target} ({type}) identified {len(findings)} suspicious indicators. "
        "Manual review of extracted artifacts and IOCs is recommended to confirm potential malicious objectives."
    )
    
    if not api_key or OpenAI is None:
        return deterministic_summary
        
    try:
        client = OpenAI(api_key=api_key)
        prompt = (
            "You are a senior defensive cybersecurity analyst and SOC lead.\n"
            f"Analyze this {type} investigation: {target}\n"
            f"Findings: {findings}\n"
            f"Extracted IOCs: {iocs}\n\n"
            "Provide an expert attack reconstruction in 5 sentences. "
            "Identify the likely threat actor objective (e.g. Credential Theft, Ransomware Staging, C2 Beaconing). "
            "Mention specific MITRE ATT&CK techniques if applicable. "
            "Be precise, technical, and use evidence-based reasoning."
        )
        
        models = [os.getenv("OPENAI_MODEL", "").strip() or "gpt-4o-mini", "gpt-4o-mini"]
        for model in models:
            try:
                text = _openai_generate_text(client, model, prompt, max_tokens=300)
                if text:
                    return text
            except Exception:
                continue
        return deterministic_summary
    except Exception:
        return deterministic_summary

def get_mitre_mapping(findings: list[str]) -> list[dict[str, str]]:
    # Simplified MITRE mapper for deterministic fallback
    mapping = []
    text = " ".join(findings).lower()
    
    patterns = {
        "T1566": ("Phishing", ["phishing", "login", "verify", "paypal", "bank"]),
        "T1059": ("Command and Scripting Interpreter", ["powershell", "cmd.exe", "bash", "script"]),
        "T1053": ("Scheduled Task/Job", ["cron", "scheduled task", "registry"]),
        "T1071": ("Application Layer Protocol", ["http", "https", "dns", "beacon"]),
        "T1027": ("Obfuscated Files or Information", ["eval", "atob", "entropy", "packed"]),
        "T1055": ("Process Injection", ["virtualalloc", "createremotethread", "writeprocessmemory"]),
        "T1547": ("Boot or Logon Autostart Execution", ["run key", "startup", "registry"]),
    }
    
    for tech_id, (name, keywords) in patterns.items():
        if any(k in text for k in keywords):
            mapping.append({"id": tech_id, "technique": name})
            
    return mapping
