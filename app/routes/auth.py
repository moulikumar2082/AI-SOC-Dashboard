from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.models import db, User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash('Invalid username or password. Please try again.', 'danger')
            return redirect(url_for('auth.login'))

        if not user.is_active:
            flash('Your account has been deactivated. Contact an administrator.', 'warning')
            return redirect(url_for('auth.login'))

        from flask import session
        login_user(user, remember=True)
        session.permanent = True
        flash(f'Welcome back, {user.username}! SOC Operations session active.', 'success')
        
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('main.dashboard')
        return redirect(next_page)

    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # New public registrations get restricted 'user' role
        # Only moulikumar holds full Primary Super Admin privileges
        role = 'admin' if username in ['moulikumar', 'chandam_mouli_kumar'] else 'user'

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('auth.register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'warning')
            return redirect(url_for('auth.register'))

        if User.query.filter_by(email=email).first():
            flash('Email address is already registered.', 'warning')
            return redirect(url_for('auth.register'))

        # Create new user
        new_user = User(username=username, email=email, role=role if role in ['analyst', 'user'] else 'user')
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        from flask import session
        login_user(new_user, remember=True)
        session.permanent = True

        flash(f'Account created successfully! Welcome to SOC Operations, {new_user.username}.', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('auth/register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out of the SOC Dashboard.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile')
@login_required
def profile():
    return render_template('auth/profile.html', user=current_user)
