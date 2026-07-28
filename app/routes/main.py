from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
from app.models import db, Log, Incident

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@main_bp.route('/dashboard')
@login_required
def dashboard():
    total_logs = Log.query.count()
    critical_alerts = Log.query.filter_by(severity='Critical').count()
    high_alerts = Log.query.filter_by(severity='High').count()
    medium_alerts = Log.query.filter_by(severity='Medium').count()
    low_alerts = Log.query.filter_by(severity='Low').count()
    active_incidents = Incident.query.filter(Incident.status.in_(['Open', 'In Progress'])).count()

    recent_critical_logs = Log.query.filter(Log.severity.in_(['Critical', 'High'])).order_by(Log.timestamp.desc()).limit(10).all()
    recent_incidents = Incident.query.order_by(Incident.created_at.desc()).limit(5).all()
    logs_history = Log.query.order_by(Log.timestamp.desc()).limit(15).all()

    return render_template('dashboard/index.html',
                           total_logs=total_logs,
                           critical_alerts=critical_alerts,
                           high_alerts=high_alerts,
                           medium_alerts=medium_alerts,
                           low_alerts=low_alerts,
                           active_incidents=active_incidents,
                           recent_logs=recent_critical_logs,
                           recent_incidents=recent_incidents,
                           logs_history=logs_history)

@main_bp.route('/api/chart-data')
@login_required
def chart_data():
    # 1. Severity Distribution
    severity_counts = db.session.query(
        Log.severity, func.count(Log.id)
    ).group_by(Log.severity).all()
    severity_dict = dict(severity_counts)
    
    severity_data = {
        'labels': ['Critical', 'High', 'Medium', 'Low', 'Info'],
        'data': [
            severity_dict.get('Critical', 0),
            severity_dict.get('High', 0),
            severity_dict.get('Medium', 0),
            severity_dict.get('Low', 0),
            severity_dict.get('Info', 0)
        ]
    }

    # 2. Attack Types Distribution
    attack_counts = db.session.query(
        Log.attack_type, func.count(Log.id)
    ).group_by(Log.attack_type).order_by(func.count(Log.id).desc()).all()

    attack_data = {
        'labels': [item[0] for item in attack_counts],
        'data': [item[1] for item in attack_counts]
    }

    # 3. Daily Alerts (Past 7 Days)
    now = datetime.now(timezone.utc)
    daily_labels = []
    daily_values = []
    
    for i in range(6, -1, -1):
        day_date = (now - timedelta(days=i)).date()
        daily_labels.append(day_date.strftime('%b %d'))
        
        start_dt = datetime.combine(day_date, datetime.min.time()).replace(tzinfo=timezone.utc)
        end_dt = datetime.combine(day_date, datetime.max.time()).replace(tzinfo=timezone.utc)
        
        cnt = Log.query.filter(Log.timestamp >= start_dt, Log.timestamp <= end_dt).count()
        daily_values.append(cnt)

    daily_data = {
        'labels': daily_labels,
        'data': daily_values
    }

    # 4. Top Source IPs
    top_ips = db.session.query(
        Log.source_ip, func.count(Log.id)
    ).group_by(Log.source_ip).order_by(func.count(Log.id).desc()).limit(7).all()

    top_ip_data = {
        'labels': [item[0] for item in top_ips],
        'data': [item[1] for item in top_ips]
    }

    return jsonify({
        'severity': severity_data,
        'attack_types': attack_data,
        'daily_alerts': daily_data,
        'top_ips': top_ip_data
    })
