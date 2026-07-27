import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, current_app
from flask_login import login_required
from app.models import Log, Incident
from app.services.report_generator import SOCReportGenerator
from app.utils.decorators import analyst_required

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/reports')
@login_required
def index():
    report_dir = current_app.config['REPORT_FOLDER']
    existing_reports = []
    
    if os.path.exists(report_dir):
        for fname in os.listdir(report_dir):
            if fname.endswith('.pdf'):
                fpath = os.path.join(report_dir, fname)
                mtime = os.path.getmtime(fpath)
                size_kb = round(os.path.getsize(fpath) / 1024, 1)
                existing_reports.append({
                    'filename': fname,
                    'created_at': mtime,
                    'size_kb': size_kb
                })
        # Sort by creation time descending
        existing_reports.sort(key=lambda x: x['created_at'], reverse=True)

    return render_template('reports/list.html', reports=existing_reports)

@reports_bp.route('/reports/generate', methods=['POST'])
@login_required
@analyst_required
def generate():
    report_type = request.form.get('report_type', 'Daily Summary')

    logs = Log.query.order_by(Log.timestamp.desc()).all()
    incidents = Incident.query.order_by(Incident.created_at.desc()).all()

    summary_stats = {
        'total_logs': len(logs),
        'critical_count': sum(1 for l in logs if l.severity == 'Critical'),
        'high_count': sum(1 for l in logs if l.severity == 'High'),
        'medium_count': sum(1 for l in logs if l.severity == 'Medium'),
        'low_count': sum(1 for l in logs if l.severity == 'Low'),
        'active_incidents': sum(1 for i in incidents if i.status in ['Open', 'In Progress'])
    }

    try:
        pdf_filename = SOCReportGenerator.generate_pdf_report(
            report_type=report_type,
            logs_data=logs,
            incidents_data=incidents,
            summary_stats=summary_stats
        )
        flash(f"PDF report '{pdf_filename}' generated successfully!", 'success')
    except Exception as e:
        flash(f"Failed to generate PDF report: {str(e)}", 'danger')

    return redirect(url_for('reports.index'))

@reports_bp.route('/reports/download/<filename>')
@login_required
def download(filename):
    report_dir = current_app.config['REPORT_FOLDER']
    return send_from_directory(report_dir, filename, as_attachment=True)
