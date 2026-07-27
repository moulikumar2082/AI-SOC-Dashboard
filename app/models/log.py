from datetime import datetime, timezone
import json
from app.models import db

class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45), default='192.168.1.1')
    user_agent = db.Column(db.String(255), nullable=True)
    event = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='Low', index=True)  # Critical, High, Medium, Low, Info
    attack_type = db.Column(db.String(50), default='Benign', index=True) # Brute Force, Port Scan, SQL Injection, XSS, Malware, Suspicious Login, Excessive Failed Logins, Benign
    risk_score = db.Column(db.Integer, default=0) # 0 to 100
    status = db.Column(db.String(30), default='Unassigned') # Unassigned, Investigating, Mitigated, False Positive, Closed
    raw_log = db.Column(db.Text, nullable=True)
    mitre_technique = db.Column(db.String(100), default='N/A')
    ai_analysis_data = db.Column(db.Text, nullable=True) # JSON string

    # Relationships
    incidents = db.relationship('Incident', backref='log', lazy='dynamic')

    @property
    def ai_analysis(self):
        if self.ai_analysis_data:
            try:
                return json.loads(self.ai_analysis_data)
            except Exception:
                return None
        return None

    @ai_analysis.setter
    def ai_analysis(self, value):
        if isinstance(value, (dict, list)):
            self.ai_analysis_data = json.dumps(value)
        else:
            self.ai_analysis_data = value

    @property
    def severity_badge_class(self):
        mapping = {
            'Critical': 'bg-danger text-white',
            'High': 'bg-warning text-dark',
            'Medium': 'bg-info text-dark',
            'Low': 'bg-secondary text-white',
            'Info': 'bg-dark text-light border border-secondary'
        }
        return mapping.get(self.severity, 'bg-secondary')

    def __repr__(self):
        return f"<Log {self.id} | IP: {self.source_ip} | Severity: {self.severity} | Attack: {self.attack_type}>"
