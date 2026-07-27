from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import db, Incident, Log, User
from app.utils.decorators import analyst_required

incidents_bp = Blueprint('incidents', __name__)

@incidents_bp.route('/incidents')
@login_required
def index():
    status_filter = request.args.get('status', '').strip()
    priority_filter = request.args.get('priority', '').strip()

    query = Incident.query

    if status_filter:
        query = query.filter(Incident.status == status_filter)
    if priority_filter:
        query = query.filter(Incident.priority == priority_filter)

    incidents = query.order_by(Incident.created_at.desc()).all()
    analysts = User.query.filter(User.role.in_(['admin', 'analyst'])).all()

    return render_template('incidents/list.html',
                           incidents=incidents,
                           analysts=analysts,
                           current_status=status_filter,
                           current_priority=priority_filter)

@incidents_bp.route('/incidents/create', methods=['GET', 'POST'])
@login_required
@analyst_required
def create():
    log_id = request.args.get('log_id', type=int)
    log_item = Log.query.get(log_id) if log_id else None

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        priority = request.form.get('priority', 'Medium')
        assigned_to_id = request.form.get('assigned_to_id', type=int)
        associated_log_id = request.form.get('log_id', type=int)

        if not title or not description:
            flash('Title and description are required.', 'danger')
            return redirect(request.url)

        incident = Incident(
            title=title,
            description=description,
            priority=priority,
            status='Open',
            assigned_to_id=assigned_to_id if assigned_to_id else current_user.id,
            log_id=associated_log_id
        )

        incident.add_timeline_note(current_user.username, f"Created security incident '{title}' with priority {priority}.")

        # If created from a log, update log status
        if associated_log_id:
            log_obj = Log.query.get(associated_log_id)
            if log_obj:
                log_obj.status = 'Investigating'

        db.session.add(incident)
        db.session.commit()

        flash(f"Incident INC-{incident.id} created successfully!", 'success')
        return redirect(url_for('incidents.detail', incident_id=incident.id))

    analysts = User.query.filter(User.role.in_(['admin', 'analyst'])).all()
    return render_template('incidents/create.html', log=log_item, analysts=analysts)

@incidents_bp.route('/incidents/<int:incident_id>', methods=['GET', 'POST'])
@login_required
def detail(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    analysts = User.query.filter(User.role.in_(['admin', 'analyst'])).all()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_status':
            new_status = request.form.get('status')
            new_priority = request.form.get('priority')
            new_assigned_to = request.form.get('assigned_to_id', type=int)
            notes = request.form.get('mitigation_notes', '').strip()

            changes = []
            if new_status and new_status != incident.status:
                changes.append(f"Status changed from '{incident.status}' to '{new_status}'")
                incident.status = new_status
            if new_priority and new_priority != incident.priority:
                changes.append(f"Priority changed from '{incident.priority}' to '{new_priority}'")
                incident.priority = new_priority
            if new_assigned_to and new_assigned_to != incident.assigned_to_id:
                new_analyst = User.query.get(new_assigned_to)
                analyst_name = new_analyst.username if new_analyst else 'Unassigned'
                changes.append(f"Assigned analyst set to '{analyst_name}'")
                incident.assigned_to_id = new_assigned_to

            if notes:
                incident.mitigation_notes = notes
                changes.append(f"Updated remediation notes: {notes}")

            if changes:
                incident.add_timeline_note(current_user.username, "; ".join(changes))
                db.session.commit()
                flash(f"Incident INC-{incident.id} updated successfully.", 'success')

        elif action == 'add_note':
            note_content = request.form.get('note', '').strip()
            if note_content:
                incident.add_timeline_note(current_user.username, note_content)
                db.session.commit()
                flash('Investigation note added to incident timeline.', 'success')

        return redirect(url_for('incidents.detail', incident_id=incident.id))

    return render_template('incidents/detail.html', incident=incident, analysts=analysts)
