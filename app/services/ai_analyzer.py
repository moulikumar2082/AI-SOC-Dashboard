import json
import logging
from flask import current_app

logger = logging.getLogger(__name__)

class AIThreatAnalyzer:
    """
    AI-Powered Security Threat Analyzer.
    Integrates with OpenAI API (or Ollama) for deep threat analysis, MITRE ATT&CK mapping,
    and remediation recommendations, with an intelligent offline fallback engine.
    """

    @classmethod
    def analyze_log(cls, log):
        """
        Analyzes a log model instance and returns a dict with AI insights.
        """
        api_key = current_app.config.get('OPENAI_API_KEY')
        
        if api_key:
            try:
                from openai import OpenAI
                client = OpenAI(api_key=api_key)
                
                prompt = f"""You are an expert Security Operations Center (SOC) AI Analyst. 
Analyze the following security log and return a JSON object ONLY with the exact keys:
- "threat_summary": (string, 1-2 sentence executive overview)
- "threat_level": (string: Critical, High, Medium, Low, or Info)
- "attack_type": (string)
- "explanation": (string, detailed technical analysis of risk and impact)
- "recommended_actions": (array of strings, step-by-step remediation guidance)
- "mitre_attack": (string, MITRE ATT&CK technique ID and name)

LOG DATA:
- ID: {log.id}
- Timestamp: {log.timestamp}
- Source IP: {log.source_ip}
- Event/Message: {log.event}
- Current Severity: {log.severity}
- Detected Attack: {log.attack_type}
- User Agent: {log.user_agent}
"""
                response = client.chat.completions.create(
                    model=current_app.config.get('OPENAI_MODEL', 'gpt-4o-mini'),
                    messages=[
                        {"role": "system", "content": "You are a cyber security threat analyst assistant. Respond strictly with valid JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    response_format={"type": "json_object"}
                )

                content = response.choices[0].message.content
                analysis_result = json.loads(content)
                return analysis_result

            except Exception as e:
                logger.warning(f"OpenAI API call failed or not configured. Using offline fallback AI analyzer: {e}")
                return cls.fallback_offline_analysis(log)
        else:
            return cls.fallback_offline_analysis(log)

    @classmethod
    def fallback_offline_analysis(cls, log):
        """
        Deterministic, offline rule-based fallback AI threat analyzer.
        Generates realistic security insights, MITRE mappings, and remediation guidance.
        """
        attack_type = log.attack_type or 'Unknown Attack'
        event_lower = (log.event or '').lower()
        ip = log.source_ip or '10.0.0.1'

        if 'sql' in attack_type.lower() or 'sqli' in event_lower or 'union' in event_lower or 'select' in event_lower:
            return {
                'threat_summary': f"Potential SQL Injection (SQLi) attempt detected originating from host {ip}.",
                'threat_level': 'Critical',
                'attack_type': 'SQL Injection',
                'explanation': f"The log entry contains malicious SQL syntax designed to manipulate application queries. If unhandled, this could allow an attacker to bypass authentication, dump sensitive database records, or modify backend data.",
                'recommended_actions': [
                    f"Immediately block IP {ip} at WAF / Perimeter Firewall.",
                    "Verify input sanitization and parameterized queries across all HTTP endpoints.",
                    "Audit database transaction logs to confirm whether query execution succeeded.",
                    "Review database permissions to ensure principle of least privilege."
                ],
                'mitre_attack': 'T1190 - Exploit Public-Facing Application'
            }

        elif 'xss' in attack_type.lower() or 'script' in event_lower or 'onerror' in event_lower:
            return {
                'threat_summary': f"Cross-Site Scripting (XSS) payload submission detected from IP {ip}.",
                'threat_level': 'High',
                'attack_type': 'Cross Site Scripting (XSS)',
                'explanation': f"An attempt to inject client-side scripts was detected. Successful execution in a user browser could lead to session hijacking, credential theft, or page defacement.",
                'recommended_actions': [
                    "Sanitize and HTML-encode all user input before rendering in DOM.",
                    "Implement a strict Content Security Policy (CSP) header.",
                    "Ensure HTTP-Only flags are set on all session cookies.",
                    "Investigate affected web application parameters."
                ],
                'mitre_attack': 'T1059.007 - JavaScript Execution'
            }

        elif 'brute' in attack_type.lower() or 'failed' in event_lower or 'password' in event_lower:
            return {
                'threat_summary': f"Brute Force / Password Spraying attack pattern identified from IP {ip}.",
                'threat_level': 'High',
                'attack_type': 'Brute Force',
                'explanation': f"High volume of failed authentication attempts detected within a short window. The adversary is attempting to guess user credentials or perform password spraying against targeted user accounts.",
                'recommended_actions': [
                    f"Temporarily block incoming connections from IP {ip}.",
                    "Enforce rate limiting and CAPTCHA challenge on authentication endpoints.",
                    "Mandate Multi-Factor Authentication (MFA) for target accounts.",
                    "Notify affected users to verify account security."
                ],
                'mitre_attack': 'T1110 - Brute Force'
            }

        elif 'port' in attack_type.lower() or 'scan' in event_lower or 'nmap' in event_lower:
            return {
                'threat_summary': f"Reconnaissance network port scan detected from IP {ip}.",
                'threat_level': 'Medium',
                'attack_type': 'Port Scanning',
                'explanation': f"The source IP probed multiple network ports in rapid succession, indicating pre-attack reconnaissance to map open services and discover vulnerabilities.",
                'recommended_actions': [
                    f"Add IP {ip} to network firewall drop rules.",
                    "Ensure non-essential external management ports (SSH, RDP, DB) are disabled or behind VPN.",
                    "Enable IDS/IPS auto-shun policies for port scanners.",
                    "Monitor target hosts for follow-up exploitation attempts."
                ],
                'mitre_attack': 'T1046 - Network Service Discovery'
            }

        elif 'malware' in attack_type.lower() or 'c2' in event_lower or 'trojan' in event_lower:
            return {
                'threat_summary': f"Malware beaconing / C2 communication indicator detected from IP {ip}.",
                'threat_level': 'Critical',
                'attack_type': 'Malware Indicators',
                'explanation': f"Suspicious network payload or user-agent matching known malware signatures was flagged. Host may be compromised and communicating with remote Command & Control infrastructure.",
                'recommended_actions': [
                    f"Isolate host {ip} from local subnet immediately.",
                    "Collect memory dump and endpoint forensic artifacts for malware triage.",
                    "Revoke session tokens and credentials used by host.",
                    "Perform full EDR antivirus scan and file system audit."
                ],
                'mitre_attack': 'T1071 - Application Layer Protocol (C2)'
            }

        else:
            return {
                'threat_summary': f"Security anomaly detected from source IP {ip}.",
                'threat_level': log.severity or 'Medium',
                'attack_type': attack_type,
                'explanation': f"General security event flagged by threat detection rules: '{log.event}'. Risk score evaluated at {log.risk_score}/100.",
                'recommended_actions': [
                    f"Review logs from IP {ip} across neighboring systems.",
                    "Determine if activity correlates with authorized administrative tasks.",
                    "Update firewall rules or application filters if malicious intent is verified."
                ],
                'mitre_attack': log.mitre_technique if log.mitre_technique != 'N/A' else 'T1078 - Valid Accounts'
            }
