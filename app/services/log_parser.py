import re
import csv
import io
from datetime import datetime, timezone

class ThreatDetectionEngine:
    """
    Automated Rule-Based Threat Detection Engine for Security Logs.
    Detects SQL Injection, XSS, Brute Force, Port Scanning, Malware Indicators, and Suspicious Logins.
    """

    # Detection Patterns
    SQLI_PATTERNS = [
        r"(?i)(\bSELECT\b.*\bFROM\b)",
        r"(?i)(\bUNION\b.*\bSELECT\b)",
        r"(?i)('\s*OR\s*['\d]=\s*['\d])",
        r"(?i)('\s*OR\s*1\s*=\s*1)",
        r"(?i)(\bDROP\s+TABLE\b)",
        r"(?i)(\bINSERT\s+INTO\b)",
        r"(?i)(\bINFORMATION_SCHEMA\b)",
        r"(?i)(--\s*$|\/\*.*\*\/)"
    ]

    XSS_PATTERNS = [
        r"(?i)(<script[^>]*>.*?</script>)",
        r"(?i)(javascript\s*:)",
        r"(?i)(onerror\s*=\s*[\"'].*?[\"'])",
        r"(?i)(onload\s*=\s*[\"'].*?[\"'])",
        r"(?i)(eval\s*\(.*?\))",
        r"(?i)(%3Cscript%3E)",
        r"(?i)(<iframe[^>]*>)"
    ]

    MALWARE_PATTERNS = [
        r"(?i)(c2\s+beacon|cobaltstrike|trojan|ransomware|mimikatz|meterpreter|payload\.exe)",
        r"(?i)(curl\s+-s\s+http|wget\s+http.*\.sh|powershell\s+-enc)",
        r"(?i)(sqlmap|nikto|dirbuster|gobuster|hydra)"
    ]

    BRUTE_FORCE_PATTERNS = [
        r"(?i)(failed\s+password|authentication\s+failed|invalid\s+user|excessive\s+failed|login_failed|event\s+4625)",
        r"(?i)(multiple\s+failed\s+attempts|brute\s*force)"
    ]

    PORT_SCAN_PATTERNS = [
        r"(?i)(port\s*scan|syn\s*scan|nmap\s*scan|stealth\s*scan|connect\s+scan|nmap)",
        r"(?i)(connection\s+refused\s+on\s+ports|probing\s+ports)"
    ]

    SUSPICIOUS_LOGIN_PATTERNS = [
        r"(?i)(root\s+login|admin\s+login\s+from|unauthorized\s+geo|anomalous\s+location|privilege\s+escalation)",
        r"(?i)(mfa\s+bypass|session\s+hijack)"
    ]

    @classmethod
    def analyze_log_entry(cls, raw_event, source_ip="127.0.0.1", user_agent=""):
        """
        Analyzes a single log line or event string and returns structured security classification.
        """
        combined_text = f"{raw_event} {user_agent}"
        
        # Check SQL Injection
        for pattern in cls.SQLI_PATTERNS:
            if re.search(pattern, combined_text):
                return {
                    'attack_type': 'SQL Injection',
                    'severity': 'Critical',
                    'risk_score': 95,
                    'mitre_technique': 'T1190 - Exploit Public-Facing Application'
                }

        # Check XSS
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, combined_text):
                return {
                    'attack_type': 'Cross Site Scripting (XSS)',
                    'severity': 'High',
                    'risk_score': 80,
                    'mitre_technique': 'T1059.007 - JavaScript Execution'
                }

        # Check Malware Indicators
        for pattern in cls.MALWARE_PATTERNS:
            if re.search(pattern, combined_text):
                return {
                    'attack_type': 'Malware Indicators',
                    'severity': 'Critical',
                    'risk_score': 98,
                    'mitre_technique': 'T1059 - Command and Scripting Interpreter'
                }

        # Check Brute Force / Failed Logins
        for pattern in cls.BRUTE_FORCE_PATTERNS:
            if re.search(pattern, combined_text):
                return {
                    'attack_type': 'Brute Force',
                    'severity': 'High',
                    'risk_score': 75,
                    'mitre_technique': 'T1110 - Brute Force'
                }

        # Check Port Scanning
        for pattern in cls.PORT_SCAN_PATTERNS:
            if re.search(pattern, combined_text):
                return {
                    'attack_type': 'Port Scanning',
                    'severity': 'Medium',
                    'risk_score': 60,
                    'mitre_technique': 'T1046 - Network Service Discovery'
                }

        # Check Suspicious Logins
        for pattern in cls.SUSPICIOUS_LOGIN_PATTERNS:
            if re.search(pattern, combined_text):
                return {
                    'attack_type': 'Suspicious Login',
                    'severity': 'High',
                    'risk_score': 78,
                    'mitre_technique': 'T1078 - Valid Accounts'
                }

        # Default / Benign
        return {
            'attack_type': 'Benign',
            'severity': 'Info',
            'risk_score': 10,
            'mitre_technique': 'N/A'
        }

    @classmethod
    def parse_uploaded_file(cls, file_stream, filename):
        """
        Parses an uploaded file (.txt, .log, or .csv) into structured Log dictionary items.
        """
        parsed_logs = []
        content = file_stream.read().decode('utf-8', errors='ignore')

        if filename.endswith('.csv'):
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                event = row.get('event') or row.get('message') or row.get('log') or str(row)
                ip = row.get('source_ip') or row.get('ip') or row.get('src_ip') or '192.168.1.100'
                dest_ip = row.get('destination_ip') or row.get('dest_ip') or '192.168.1.1'
                ua = row.get('user_agent') or ''
                
                analysis = cls.analyze_log_entry(event, ip, ua)
                parsed_logs.append({
                    'timestamp': datetime.now(timezone.utc),
                    'source_ip': ip,
                    'destination_ip': dest_ip,
                    'user_agent': ua,
                    'event': event,
                    'severity': row.get('severity') or analysis['severity'],
                    'attack_type': row.get('attack_type') or analysis['attack_type'],
                    'risk_score': int(row.get('risk_score', analysis['risk_score'])),
                    'mitre_technique': analysis['mitre_technique'],
                    'raw_log': event,
                    'status': 'Unassigned'
                })
        else:
            # Plain text or .log file line-by-line parsing
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Extract IP if present via regex
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                source_ip = ip_match.group(0) if ip_match else '10.0.0.15'

                analysis = cls.analyze_log_entry(line, source_ip)
                parsed_logs.append({
                    'timestamp': datetime.now(timezone.utc),
                    'source_ip': source_ip,
                    'destination_ip': '192.168.1.1',
                    'user_agent': 'Log-Ingestor-Service/1.0',
                    'event': line,
                    'severity': analysis['severity'],
                    'attack_type': analysis['attack_type'],
                    'risk_score': analysis['risk_score'],
                    'mitre_technique': analysis['mitre_technique'],
                    'raw_log': line,
                    'status': 'Unassigned'
                })

        return parsed_logs
