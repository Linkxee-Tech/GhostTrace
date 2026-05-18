from typing import List
import os
from app.services.llm_fallback import generate_with_fallback


def explain_behavior(target: str, type: str, findings: list[str], iocs: dict) -> str:
    # This function now acts as a high-level investigator
    api_key = os.getenv("OPENAI_API_KEY")
    deterministic_summary = (
        f"Forensic investigation of {target} ({type}) identified {len(findings)} suspicious indicators. "
        "Manual review of extracted artifacts and IOCs is recommended to confirm potential malicious objectives."
    )
    
    if not api_key and not os.getenv("GROQ_API_KEY", "").strip():
        return deterministic_summary

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
    text = generate_with_fallback(prompt, max_tokens=300, primary_model="gpt-4o-mini")
    return text or deterministic_summary

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
