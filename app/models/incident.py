from datetime import datetime, timezone
import json
from app.models import db

class Incident(db.Model):
    __tablename__ = 'incidents'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), default='Medium', index=True) # Critical, High, Medium, Low
    status = db.Column(db.String(30), default='Open', index=True) # Open, In Progress, Resolved, Closed
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    log_id = db.Column(db.Integer, db.ForeignKey('logs.id'), nullable=True)
    mitigation_notes = db.Column(db.Text, nullable=True)
    timeline_data = db.Column(db.Text, nullable=True) # JSON array of event logs / notes
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    @property
    def timeline(self):
        if self.timeline_data:
            try:
                return json.loads(self.timeline_data)
            except Exception:
                return []
        return []

    def add_timeline_note(self, author, note):
        current = self.timeline
        entry = {
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
            'author': author,
            'note': note
        }
        current.append(entry)
        self.timeline_data = json.dumps(current)

    @property
    def priority_badge_class(self):
        mapping = {
            'Critical': 'bg-danger text-white',
            'High': 'bg-warning text-dark',
            'Medium': 'bg-info text-dark',
            'Low': 'bg-secondary text-white'
        }
        return mapping.get(self.priority, 'bg-secondary')

    @property
    def status_badge_class(self):
        mapping = {
            'Open': 'bg-danger text-white border border-danger',
            'In Progress': 'bg-primary text-white border border-primary',
            'Resolved': 'bg-success text-white border border-success',
            'Closed': 'bg-secondary text-light border border-secondary'
        }
        return mapping.get(self.status, 'bg-secondary')

    def __repr__(self):
        return f"<Incident {self.id} | {self.title} | Status: {self.status}>"
