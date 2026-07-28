import os
import unittest
from datetime import datetime, timezone
from app import create_app
from app.config import Config
from app.models import db, User, Log, Incident
from app.services.log_parser import ThreatDetectionEngine
from app.services.ai_analyzer import AIThreatAnalyzer
from app.services.report_generator import SOCReportGenerator

class TestSOCDashboard(unittest.TestCase):
    def setUp(self):
        class TestConfig(Config):
            TESTING = True
            SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
            WTF_CSRF_ENABLED = False
            SECRET_KEY = 'test-key'

        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_sample_seeding_and_auth(self):
        """Test database seeding and authentication logic."""
        admin = User.query.filter_by(username='admin').first()
        self.assertIsNotNone(admin)
        self.assertTrue(admin.check_password('Admin@123'))
        self.assertTrue(admin.is_admin)

        analyst = User.query.filter_by(username='analyst').first()
        self.assertIsNotNone(analyst)
        self.assertTrue(analyst.is_analyst)

    def test_threat_detection_engine(self):
        """Test threat detection rules for SQLi, XSS, Brute Force, and Malware."""
        # 1. SQLi test
        sqli_res = ThreatDetectionEngine.analyze_log_entry("SELECT * FROM users WHERE username = 'admin' UNION SELECT 1, 2--")
        self.assertEqual(sqli_res['attack_type'], 'SQL Injection')
        self.assertEqual(sqli_res['severity'], 'Critical')

        # 2. XSS test
        xss_res = ThreatDetectionEngine.analyze_log_entry("POST /comment payload=<script>alert('xss')</script>")
        self.assertEqual(xss_res['attack_type'], 'Cross Site Scripting (XSS)')
        self.assertEqual(xss_res['severity'], 'High')

        # 3. Brute Force test
        bf_res = ThreatDetectionEngine.analyze_log_entry("SSHD: Failed password attempts for root from 192.168.1.100")
        self.assertEqual(bf_res['attack_type'], 'Brute Force')

        # 4. Port Scan test
        scan_res = ThreatDetectionEngine.analyze_log_entry("Nmap port scan probing ports 22, 80, 443, 3306")
        self.assertEqual(scan_res['attack_type'], 'Port Scanning')

    def test_ai_analyzer_offline_fallback(self):
        """Test AI analyzer fallback output."""
        log = Log(
            source_ip='185.220.101.5',
            event="GET /api/v1/data?id=' OR 1=1--",
            severity='Critical',
            attack_type='SQL Injection',
            risk_score=95
        )
        ai_res = AIThreatAnalyzer.fallback_offline_analysis(log)
        self.assertIn('threat_summary', ai_res)
        self.assertEqual(ai_res['attack_type'], 'SQL Injection')
        self.assertEqual(ai_res['threat_level'], 'Critical')
        self.assertTrue(len(ai_res['recommended_actions']) > 0)

    def test_report_generator(self):
        """Test ReportLab PDF report creation."""
        logs = Log.query.all()
        incidents = Incident.query.all()
        stats = {'total_logs': len(logs), 'critical_count': 5, 'high_count': 10, 'medium_count': 2, 'low_count': 0, 'active_incidents': 2}
        
        pdf_file = SOCReportGenerator.generate_pdf_report('Daily Summary', logs_data=logs, incidents_data=incidents, summary_stats=stats)
        self.assertTrue(pdf_file.endswith('.pdf'))
        
        full_path = os.path.join(self.app.config['REPORT_FOLDER'], pdf_file)
        self.assertTrue(os.path.exists(full_path))

    def test_report_routes(self):
        """Test generating and downloading PDF reports via routes."""
        # Login as Admin (who is an analyst)
        self.client.post('/login', data={'username': 'admin', 'password': 'Admin@123'}, follow_redirects=True)
        
        # Test report index
        idx_res = self.client.get('/reports')
        self.assertEqual(idx_res.status_code, 200)

        # Test generating PDF (direct streaming response)
        gen_res = self.client.post('/reports/generate', data={'report_type': 'Daily Summary'})
        self.assertEqual(gen_res.status_code, 200)
        self.assertEqual(gen_res.mimetype, 'application/pdf')
        self.assertTrue(gen_res.data.startswith(b'%PDF'))

        # Find generated filename in folder
        report_dir = os.path.abspath(self.app.config['REPORT_FOLDER'])
        files = [f for f in os.listdir(report_dir) if f.endswith('.pdf')]
        self.assertTrue(len(files) > 0)
        
        # Test download endpoint
        dl_res = self.client.get(f'/reports/download/{files[0]}')
        self.assertEqual(dl_res.status_code, 200)
        self.assertEqual(dl_res.mimetype, 'application/pdf')
        self.assertIn('attachment', dl_res.headers.get('Content-Disposition', ''))

if __name__ == '__main__':
    unittest.main()
