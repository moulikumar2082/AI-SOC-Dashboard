import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, send_file, current_app
from flask_login import login_required
from werkzeug.utils import secure_filename
from app.models import Log, Incident
from app.services.report_generator import SOCReportGenerator
from app.utils.decorators import analyst_required

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/reports')
@login_required
def index():
    report_dir = os.path.abspath(current_app.config['REPORT_FOLDER'])
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

    download_file = request.args.get('download', '')
    return render_template('reports/list.html', reports=existing_reports, download_file=download_file)

@reports_bp.route('/reports/generate', methods=['POST'])
@login_required
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
        report_dir = os.path.abspath(current_app.config['REPORT_FOLDER'])
        file_path = os.path.join(report_dir, pdf_filename)

        return send_file(
            file_path,
            as_attachment=True,
            download_name=pdf_filename,
            mimetype='application/pdf'
        )
    except Exception as e:
        flash(f"Failed to generate PDF report: {str(e)}", 'danger')
        return redirect(url_for('reports.index'))

@reports_bp.route('/reports/download/<filename>')
@login_required
def download(filename):
    safe_name = secure_filename(filename)
    report_dir = os.path.abspath(current_app.config['REPORT_FOLDER'])
    file_path = os.path.join(report_dir, safe_name)

    if not os.path.exists(file_path):
        report_type = 'Daily Summary'
        if 'Weekly_Summary' in safe_name:
            report_type = 'Weekly Summary'
        elif 'Incident_Report' in safe_name:
            report_type = 'Incident Report'
        elif 'Attack_Statistics' in safe_name:
            report_type = 'Attack Statistics'

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
            SOCReportGenerator.generate_pdf_report(
                report_type=report_type,
                logs_data=logs,
                incidents_data=incidents,
                summary_stats=summary_stats,
                filename=safe_name
            )
        except Exception:
            flash(f"Requested PDF report '{safe_name}' could not be generated.", 'danger')
            return redirect(url_for('reports.index'))

    return send_from_directory(
        report_dir,
        safe_name,
        as_attachment=True,
        mimetype='application/pdf'
    )


