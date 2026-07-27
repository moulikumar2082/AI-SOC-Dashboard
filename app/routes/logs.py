from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime
from app.models import db, Log, Incident, User
from app.services.log_parser import ThreatDetectionEngine
from app.services.ai_analyzer import AIThreatAnalyzer
from app.utils.decorators import analyst_required

logs_bp = Blueprint('logs', __name__)

@logs_bp.route('/logs')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    severity_filter = request.args.get('severity', '').strip()
    attack_filter = request.args.get('attack_type', '').strip()
    ip_filter = request.args.get('ip', '').strip()
    search_query = request.args.get('q', '').strip()

    query = Log.query

    if severity_filter:
        query = query.filter(Log.severity == severity_filter)
    if attack_filter:
        query = query.filter(Log.attack_type == attack_filter)
    if ip_filter:
        query = query.filter(Log.source_ip.contains(ip_filter))
    if search_query:
        query = query.filter(
            (Log.event.contains(search_query)) |
            (Log.source_ip.contains(search_query)) |
            (Log.attack_type.contains(search_query))
        )

    pagination = query.order_by(Log.timestamp.desc()).paginate(page=page, per_page=15, error_out=False)
    logs = pagination.items

    # Distinct values for dropdown filters
    severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
    attack_types = [item[0] for item in db.session.query(Log.attack_type).distinct().all()]

    return render_template('logs/list.html',
                           logs=logs,
                           pagination=pagination,
                           severities=severities,
                           attack_types=attack_types,
                           current_severity=severity_filter,
                           current_attack=attack_filter,
                           current_ip=ip_filter,
                           search_query=search_query)

@logs_bp.route('/logs/upload', methods=['GET', 'POST'])
@login_required
@analyst_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part in request.', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'warning')
            return redirect(request.url)

        if file and ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in {'txt', 'log', 'csv'}):
            filename = secure_filename(file.filename)
            try:
                parsed_logs = ThreatDetectionEngine.parse_uploaded_file(file.stream, filename)
                
                logs_to_add = []
                for entry in parsed_logs:
                    log_item = Log(
                        timestamp=entry['timestamp'],
                        source_ip=entry['source_ip'],
                        destination_ip=entry['destination_ip'],
                        user_agent=entry['user_agent'],
                        event=entry['event'],
                        severity=entry['severity'],
                        attack_type=entry['attack_type'],
                        risk_score=entry['risk_score'],
                        mitre_technique=entry['mitre_technique'],
                        raw_log=entry['raw_log'],
                        status=entry['status']
                    )
                    # Generate AI threat analysis for suspicious uploaded logs
                    if log_item.severity in ['Critical', 'High', 'Medium']:
                        log_item.ai_analysis = AIThreatAnalyzer.fallback_offline_analysis(log_item)
                        
                    logs_to_add.append(log_item)

                db.session.add_all(logs_to_add)
                db.session.commit()

                flash(f"Successfully processed {len(logs_to_add)} log entries from '{filename}'. Automated Threat Engine flags applied!", 'success')
                return redirect(url_for('logs.index'))
            except Exception as e:
                db.session.rollback()
                flash(f"Error parsing log file: {str(e)}", 'danger')
                return redirect(request.url)
        else:
            flash('Invalid file extension. Please upload a .txt, .log, or .csv file.', 'danger')
            return redirect(request.url)

    return render_template('logs/upload.html')

@logs_bp.route('/logs/<int:log_id>')
@login_required
def detail(log_id):
    log = Log.query.get_or_404(log_id)
    analysts = User.query.filter(User.role.in_(['admin', 'analyst'])).all()
    
    # Run AI analysis if not present
    if not log.ai_analysis:
        analysis = AIThreatAnalyzer.analyze_log(log)
        log.ai_analysis = analysis
        db.session.commit()

    return render_template('logs/detail.html', log=log, analysts=analysts)

@logs_bp.route('/logs/<int:log_id>/delete', methods=['POST'])
@login_required
@analyst_required
def delete(log_id):
    log = Log.query.get_or_404(log_id)
    db.session.delete(log)
    db.session.commit()
    flash(f"Log ID #{log_id} has been permanently deleted.", 'success')
    return redirect(url_for('logs.index'))
