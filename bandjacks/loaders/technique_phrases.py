"""Technique phrase mappings for improved text-to-technique matching."""

from typing import Dict, List, Set, Tuple
import re

# Common technique phrases mapped to ATT&CK technique IDs
TECHNIQUE_PHRASES: Dict[str, List[str]] = {
    # Initial Access
    "spearphishing": ["T1566", "T1566.001"],
    "spear phishing": ["T1566", "T1566.001"],
    "phishing email": ["T1566", "T1566.001"],
    "phishing campaign": ["T1566"],
    "malicious attachment": ["T1566.001"],
    "phishing link": ["T1566.002"],
    "phishing url": ["T1566.002"],
    "watering hole": ["T1189"],
    "waterhole attack": ["T1189"],
    "drive-by compromise": ["T1189"],
    "drive by download": ["T1189"],
    "exploit public facing": ["T1190"],
    "external remote services": ["T1133"],
    "supply chain": ["T1195"],
    
    # Execution
    "powershell": ["T1059.001"],
    "powershell script": ["T1059.001"],
    "powershell command": ["T1059.001"],
    "windows command shell": ["T1059.003"],
    "cmd.exe": ["T1059.003"],
    "command prompt": ["T1059.003"],
    "batch script": ["T1059.003"],
    "bash script": ["T1059.004"],
    "shell script": ["T1059.004"],
    "python script": ["T1059.006"],
    "javascript": ["T1059.007"],
    "visual basic": ["T1059.005"],
    "vbscript": ["T1059.005"],
    "vba macro": ["T1059.005"],
    "macro": ["T1059.005", "T1137"],
    "wmi": ["T1047"],
    "windows management instrumentation": ["T1047"],
    "scheduled task": ["T1053.005"],
    "schtasks": ["T1053.005"],
    "cron job": ["T1053.003"],
    "at command": ["T1053.002"],
    
    # Persistence
    "registry run key": ["T1547.001"],
    "registry autostart": ["T1547.001"],
    "startup folder": ["T1547.001"],
    "boot or logon": ["T1547"],
    "create service": ["T1543.003"],
    "new service": ["T1543.003"],
    "windows service": ["T1543.003"],
    "systemd service": ["T1543.002"],
    "account creation": ["T1136"],
    "create account": ["T1136"],
    "new user account": ["T1136.001"],
    "backdoor": ["T1505", "T1554"],
    "web shell": ["T1505.003"],
    "webshell": ["T1505.003"],
    
    # Privilege Escalation
    "privilege escalation": ["T1068", "T1078"],
    "uac bypass": ["T1548.002"],
    "bypass uac": ["T1548.002"],
    "dll hijacking": ["T1574.001"],
    "dll search order": ["T1574.001"],
    "token impersonation": ["T1134"],
    "access token": ["T1134"],
    "sudo": ["T1548.003"],
    
    # Defense Evasion
    "process injection": ["T1055"],
    "dll injection": ["T1055.001"],
    "process hollowing": ["T1055.012"],
    "code signing": ["T1553"],
    "timestomp": ["T1070.006"],
    "timestomping": ["T1070.006"],
    "clear logs": ["T1070.001"],
    "delete logs": ["T1070.001"],
    "indicator removal": ["T1070"],
    "disable security tools": ["T1562.001"],
    "disable antivirus": ["T1562.001"],
    "disable defender": ["T1562.001"],
    "bypass amsi": ["T1562.001"],
    "masquerading": ["T1036"],
    "hidden files": ["T1564.001"],
    "hide artifacts": ["T1564"],
    
    # Credential Access
    "credential dumping": ["T1003"],
    "dump credentials": ["T1003"],
    "lsass dump": ["T1003.001"],
    "dump lsass": ["T1003.001"],
    "mimikatz": ["T1003"],
    "hashdump": ["T1003"],
    "password hash": ["T1003"],
    "ntlm hash": ["T1003"],
    "sam database": ["T1003.002"],
    "cached credentials": ["T1003.005"],
    "keylogging": ["T1056.001"],
    "keylogger": ["T1056.001"],
    "input capture": ["T1056"],
    "credential stuffing": ["T1110.004"],
    "password spray": ["T1110.003"],
    "password spraying": ["T1110.003"],
    "brute force": ["T1110"],
    "browser cookies": ["T1539"],
    "browser passwords": ["T1555.003"],
    
    # Discovery
    "network scanning": ["T1046"],
    "port scanning": ["T1046"],
    "port scan": ["T1046"],
    "service discovery": ["T1046"],
    "system information": ["T1082"],
    "process discovery": ["T1057"],
    "process list": ["T1057"],
    "file discovery": ["T1083"],
    "network configuration": ["T1016"],
    "ipconfig": ["T1016"],
    "ifconfig": ["T1016"],
    "domain enumeration": ["T1087.002"],
    "user enumeration": ["T1087"],
    "enumerate users": ["T1087"],
    "account discovery": ["T1087"],
    "query registry": ["T1012"],
    "registry query": ["T1012"],
    
    # Lateral Movement
    "lateral movement": ["T1021"],
    "rdp": ["T1021.001"],
    "remote desktop": ["T1021.001"],
    "ssh": ["T1021.004"],
    "smb": ["T1021.002"],
    "psexec": ["T1021.002", "T1570"],
    "wmi lateral": ["T1021.006"],
    "pass the hash": ["T1550.002"],
    "pass the ticket": ["T1550.003"],
    "golden ticket": ["T1558.001"],
    "silver ticket": ["T1558.002"],
    "kerberoasting": ["T1558.003"],
    
    # Collection
    "data collection": ["T1005", "T1074"],
    "data staged": ["T1074"],
    "data staging": ["T1074"],
    "screen capture": ["T1113"],
    "screenshot": ["T1113"],
    "clipboard data": ["T1115"],
    "audio capture": ["T1123"],
    "video capture": ["T1125"],
    "keystrokes": ["T1056.001"],
    "email collection": ["T1114"],
    "browser data": ["T1217"],
    
    # Command and Control
    "command and control": ["T1071"],
    "c2": ["T1071"],
    "c&c": ["T1071"],
    "web protocols": ["T1071.001"],
    "dns tunneling": ["T1071.004"],
    "dns tunnel": ["T1071.004"],
    "encrypted channel": ["T1573"],
    "proxy": ["T1090"],
    "domain fronting": ["T1090.004"],
    "dead drop resolver": ["T1102.001"],
    "web service": ["T1102"],
    "remote access": ["T1219"],
    "cobalt strike beacon": ["T1071", "T1105"],
    
    # Exfiltration
    "exfiltration": ["T1041"],
    "data exfiltration": ["T1041"],
    "exfiltrate data": ["T1041"],
    "alternative protocol": ["T1048"],
    "exfiltration over c2": ["T1041"],
    "automated exfiltration": ["T1020"],
    "scheduled transfer": ["T1029"],
    
    # Impact
    "ransomware": ["T1486"],
    "data encrypted": ["T1486"],
    "encrypt files": ["T1486"],
    "data destruction": ["T1485"],
    "disk wipe": ["T1561"],
    "defacement": ["T1491"],
    "dos attack": ["T1499"],
    "denial of service": ["T1499"],
    "resource hijacking": ["T1496"],
    "cryptomining": ["T1496"],
}

# Tool names mapped to commonly associated techniques
TOOL_TECHNIQUE_HINTS: Dict[str, List[str]] = {
    # Credential Tools
    "mimikatz": ["T1003", "T1003.001", "T1558.003", "T1550.002"],
    "lazagne": ["T1555", "T1555.003"],
    "rubeus": ["T1558", "T1558.003", "T1558.001"],
    "sharpkatz": ["T1003", "T1003.001"],
    
    # Frameworks
    "cobalt strike": ["T1055", "T1059.003", "T1071", "T1105", "T1570"],
    "metasploit": ["T1055", "T1021", "T1210", "T1203"],
    "empire": ["T1059.001", "T1086", "T1055"],
    "powersploit": ["T1059.001", "T1003", "T1055"],
    
    # Discovery Tools
    "bloodhound": ["T1087", "T1069", "T1482", "T1201"],
    "sharphound": ["T1087", "T1069", "T1482"],
    "adfind": ["T1087.002", "T1069", "T1018"],
    "nltest": ["T1482", "T1018"],
    
    # Lateral Movement
    "psexec": ["T1021.002", "T1570", "T1035"],
    "wmiexec": ["T1047", "T1021.006"],
    "smbexec": ["T1021.002"],
    "sharpwmi": ["T1047", "T1021.006"],
    
    # Persistence
    "schtasks": ["T1053.005"],
    "at.exe": ["T1053.002"],
    
    # Network Tools
    "nmap": ["T1046", "T1040"],
    "masscan": ["T1046"],
    "netcat": ["T1095", "T1571"],
    "nc.exe": ["T1095", "T1571"],
    
    # Post-Exploitation
    "sharpup": ["T1082", "T1057", "T1083"],
    "seatbelt": ["T1082", "T1057", "T1518"],
    "winpeas": ["T1082", "T1057", "T1518"],
}

# Behavioral patterns that suggest techniques
BEHAVIORAL_PATTERNS: Dict[str, List[str]] = {
    "download and execute": ["T1105", "T1059"],
    "download and run": ["T1105", "T1059"],
    "fetch and execute": ["T1105", "T1059"],
    "scan for open ports": ["T1046"],
    "enumerate domain users": ["T1087.002"],
    "enumerate local users": ["T1087.001"],
    "create new service": ["T1543.003"],
    "modify registry": ["T1112", "T1547.001"],
    "disable security": ["T1562.001"],
    "bypass security": ["T1562"],
    "steal credentials": ["T1003", "T1555"],
    "harvest credentials": ["T1003", "T1555"],
    "establish persistence": ["T1547", "T1543", "T1053"],
    "maintain persistence": ["T1547", "T1543", "T1053"],
    "move laterally": ["T1021", "T1570"],
    "pivot to": ["T1021", "T1570"],
    "beacon back": ["T1071", "T1102"],
    "phone home": ["T1071", "T1102"],
    "living off the land": ["T1218", "T1036"],
    "lolbas": ["T1218", "T1036"],
    "lolbin": ["T1218", "T1036"],
}


def normalize_phrase(phrase: str) -> str:
    """Normalize a phrase for matching (lowercase, remove extra spaces, handle punctuation)."""
    # Convert to lowercase
    phrase = phrase.lower()
    # Replace common separators with space
    phrase = re.sub(r'[-_/\\]+', ' ', phrase)
    # Remove apostrophes in contractions
    phrase = re.sub(r"'", '', phrase)
    # Collapse multiple spaces
    phrase = re.sub(r'\s+', ' ', phrase)
    return phrase.strip()


def find_technique_phrases(text: str) -> Dict[str, List[str]]:
    """
    Find technique phrases in text and return matching technique IDs.
    
    Args:
        text: Input text to search for phrases
        
    Returns:
        Dictionary mapping found phrases to technique IDs
    """
    text_lower = text.lower()
    found = {}
    
    # Check technique phrases
    for phrase, techniques in TECHNIQUE_PHRASES.items():
        normalized = normalize_phrase(phrase)
        if normalized in text_lower or phrase in text_lower:
            found[phrase] = techniques
    
    # Check behavioral patterns
    for pattern, techniques in BEHAVIORAL_PATTERNS.items():
        if pattern in text_lower:
            found[pattern] = techniques
    
    return found


def find_tool_mentions(text: str) -> Dict[str, List[str]]:
    """
    Find tool mentions in text and return associated technique IDs.
    
    Args:
        text: Input text to search for tool names
        
    Returns:
        Dictionary mapping found tools to technique IDs
    """
    text_lower = text.lower()
    found = {}
    
    for tool, techniques in TOOL_TECHNIQUE_HINTS.items():
        if tool in text_lower:
            found[tool] = techniques
    
    return found


def get_all_technique_hints(text: str) -> Set[str]:
    """
    Get all technique IDs hinted at by phrases and tools in the text.
    
    Args:
        text: Input text to analyze
        
    Returns:
        Set of unique technique IDs
    """
    all_techniques = set()
    
    # Get techniques from phrases
    phrase_matches = find_technique_phrases(text)
    for techniques in phrase_matches.values():
        all_techniques.update(techniques)
    
    # Get techniques from tools
    tool_matches = find_tool_mentions(text)
    for techniques in tool_matches.values():
        all_techniques.update(techniques)
    
    return all_techniques


def calculate_phrase_relevance(text: str, technique_id: str) -> Tuple[float, str]:
    """
    Calculate relevance score for a technique based on phrase matches.
    
    Args:
        text: Input text
        technique_id: ATT&CK technique ID (e.g., T1059.001)
        
    Returns:
        Tuple of (score 0-100, matching phrase or "")
    """
    text_lower = text.lower()
    
    # Extract base technique ID (T1059 from T1059.001)
    base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
    
    # Check for exact ID match in phrases
    for phrase, techniques in TECHNIQUE_PHRASES.items():
        normalized = normalize_phrase(phrase)
        if (normalized in text_lower or phrase in text_lower):
            if technique_id in techniques:
                return (100.0, phrase)
            elif base_id in techniques:
                return (75.0, phrase)
    
    # Check behavioral patterns
    for pattern, techniques in BEHAVIORAL_PATTERNS.items():
        if pattern in text_lower:
            if technique_id in techniques or base_id in techniques:
                return (80.0, pattern)
    
    # Check tool associations
    for tool, techniques in TOOL_TECHNIQUE_HINTS.items():
        if tool in text_lower:
            if technique_id in techniques:
                return (60.0, f"tool:{tool}")
            elif base_id in techniques:
                return (40.0, f"tool:{tool}")
    
    return (0.0, "")


def expand_technique_text(technique_name: str) -> str:
    """
    Expand a technique name with common phrases and synonyms for better matching.
    
    Args:
        technique_name: Original technique name from ATT&CK
        
    Returns:
        Expanded text including synonyms and common phrases
    """
    expanded = [technique_name]
    
    # Add common variations based on technique name patterns
    name_lower = technique_name.lower()
    
    # Handle specific technique name patterns
    if "powershell" in name_lower:
        expanded.extend(["powershell script", "powershell command", "ps1", "pwsh"])
    elif "command" in name_lower and "shell" in name_lower:
        expanded.extend(["cmd.exe", "command prompt", "cmd shell"])
    elif "spearphishing" in name_lower:
        expanded.extend(["spear phishing", "targeted phishing", "phishing email"])
    elif "credential" in name_lower and "dump" in name_lower:
        expanded.extend(["dump credentials", "credential theft", "cred dump"])
    elif "registry" in name_lower:
        expanded.extend(["windows registry", "reg key", "registry modification"])
    elif "lateral movement" in name_lower:
        expanded.extend(["move laterally", "lateral spread", "pivot"])
    
    return " ".join(expanded)