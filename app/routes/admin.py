from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import db, User, Log, Incident
from app.utils.decorators import admin_required

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin')
@admin_bp.route('/admin/users')
@login_required
@admin_required
def users():
    users_list = User.query.order_by(User.created_at.desc()).all()
    total_logs = Log.query.count()
    total_incidents = Incident.query.count()
    
    return render_template('admin/users.html',
                           users=users_list,
                           total_logs=total_logs,
                           total_incidents=total_incidents)

@admin_bp.route('/admin/users/create', methods=['POST'])
@login_required
@admin_required
def create_user():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user')

    if User.query.filter_by(username=username).first():
        flash(f"Username '{username}' already exists.", 'danger')
        return redirect(url_for('admin.users'))

    if User.query.filter_by(email=email).first():
        flash(f"Email '{email}' already exists.", 'danger')
        return redirect(url_for('admin.users'))

    new_user = User(username=username, email=email, role=role)
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

    flash(f"User account '{username}' created successfully as role '{role}'.", 'success')
    return redirect(url_for('admin.users'))

@admin_bp.route('/admin/users/<int:user_id>/update-role', methods=['POST'])
@login_required
@admin_required
def update_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    
    if user.username == 'moulikumar' and current_user.username != 'moulikumar':
        flash("Only Chandam Mouli Kumar can modify the Primary Super Admin role.", 'warning')
        return redirect(url_for('admin.users'))

    if new_role in ['admin', 'analyst', 'user']:
        user.role = new_role
        db.session.commit()
        flash(f"Role for '{user.username}' updated to '{new_role}'.", 'success')
    return redirect(url_for('admin.users'))

@admin_bp.route('/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_status(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id or user.username == 'moulikumar':
        flash("The Super Admin account cannot be deactivated.", 'warning')
        return redirect(url_for('admin.users'))

    user.is_active = not user.is_active
    db.session.commit()
    status_str = "activated" if user.is_active else "deactivated"
    flash(f"User '{user.username}' has been {status_str}.", 'info')
    return redirect(url_for('admin.users'))

@admin_bp.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", 'warning')
        return redirect(url_for('admin.users'))

    db.session.delete(user)
    db.session.commit()
    flash(f"User '{user.username}' deleted permanently.", 'success')
    return redirect(url_for('admin.users'))

@admin_bp.route('/admin/clear-logs', methods=['POST'])
@login_required
@admin_required
def clear_logs():
    Log.query.delete()
    db.session.commit()
    flash('All security telemetry logs purged from system.', 'warning')
    return redirect(url_for('admin.users'))
