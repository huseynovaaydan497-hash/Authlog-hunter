"""MITRE ATT&CK (Enterprise) techniques referenced by the detection rules."""

from __future__ import annotations

# technique id -> (name, primary tactic shown in reports)
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1078.003": ("Valid Accounts: Local Accounts", "Initial Access"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence"),
    "T1098.007": ("Account Manipulation: Additional Local or Domain Groups", "Privilege Escalation"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "Persistence"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation"),
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access"),
    "T1070.002": ("Indicator Removal: Clear Linux or Mac System Logs", "Defense Evasion"),
    "T1070.003": ("Indicator Removal: Clear Command History", "Defense Evasion"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
}


def name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, ("Unknown technique", ""))[0]


def tactic(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, ("", "Unknown"))[1]


def url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def label(technique_id: str) -> str:
    return f"{technique_id} {name(technique_id)}"
