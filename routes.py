import os
import json
import uuid
import pandas as pd
from datetime import datetime, timezone, timedelta
from flask import (Blueprint, render_template, redirect, url_for, flash,
                   request, jsonify, session, current_app)
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_

from models import ( db, Admin, Employee, Department, UploadHistory, ActivityLog, EmailTemplate, Campaign,CampaignTarget)

main = Blueprint('main', __name__)
auth = Blueprint('auth', __name__)


IST = timezone(timedelta(hours=5, minutes=30))


@main.app_template_filter('to_ist')
def to_ist_filter(dt, fmt='%d %b %Y, %H:%M'):
    """Convert a stored UTC datetime to IST for display in templates."""
    if dt is None:
        return '—'
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST).strftime(fmt)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def log_activity(action, entity_type=None, entity_id=None, description=None):
    """Record an audit log entry for the current admin."""
    log = ActivityLog(
        admin_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id else None,
        description=description,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string[:255] if request.user_agent else None,
    )
    db.session.add(log)
    db.session.commit()


def allowed_file(filename):
    allowed = current_app.config['ALLOWED_EXTENSIONS']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


def allowed_attachment_file(filename):
    allowed = current_app.config['ALLOWED_ATTACHMENT_EXTENSIONS']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


REQUIRED_CSV_COLUMNS = {
    'employee_id', 'employee_name', 'email', 'department', 'designation', 'office_location'
}


# ─── Auth Routes ─────────────────────────────────────────────────────────────

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        admin = Admin.query.filter_by(username=username, is_active=True).first()

        if admin and admin.check_password(password):
            if admin.totp_enabled:
                # Store pending login in session; redirect to 2FA verify step
                session['_2fa_pending_user_id'] = admin.id
                session['_2fa_remember'] = remember
                return redirect(url_for('auth.two_factor_verify'))
            else:
                login_user(admin, remember=remember)
                admin.last_login = datetime.now(timezone.utc)
                db.session.commit()
                log_activity('LOGIN', description=f'Admin "{username}" logged in')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('main.dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@auth.route('/2fa/verify', methods=['GET', 'POST'])
def two_factor_verify():
    """Step-2 of login: validate TOTP code when 2FA is enabled."""
    import pyotp

    user_id = session.get('_2fa_pending_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    admin = Admin.query.get(user_id)
    if not admin or not admin.totp_enabled:
        session.pop('_2fa_pending_user_id', None)
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = request.form.get('totp_code', '').strip().replace(' ', '')
        totp = pyotp.TOTP(admin.totp_secret)
        if totp.verify(code, valid_window=1):
            remember = session.pop('_2fa_remember', False)
            session.pop('_2fa_pending_user_id', None)
            login_user(admin, remember=remember)
            admin.last_login = datetime.now(timezone.utc)
            db.session.commit()
            log_activity('LOGIN', description=f'Admin "{admin.username}" logged in (2FA)')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid or expired code. Please try again.', 'danger')

    return render_template('auth/two_factor_verify.html')


@auth.route('/logout')
@login_required
def logout():
    log_activity('LOGOUT', description=f'Admin "{current_user.username}" logged out')
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))


# ─── Forgot / Reset Password ──────────────────────────────────────────────────

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

RESET_TOKEN_MAX_AGE = 1800  # 30 minutes


def _get_reset_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])


def generate_reset_token(admin):
    s = _get_reset_serializer()
    return s.dumps(admin.email, salt='password-reset-salt')


def verify_reset_token(token, max_age=RESET_TOKEN_MAX_AGE):
    s = _get_reset_serializer()
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None
    return Admin.query.filter_by(email=email, is_active=True).first()


@auth.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        from mail_service import send_password_reset_email

        email = request.form.get('email', '').strip().lower()
        admin = Admin.query.filter_by(email=email, is_active=True).first()

        if admin:
            token = generate_reset_token(admin)
            reset_url = url_for('auth.reset_password', token=token, _external=True)
            send_password_reset_email(admin, reset_url)
            log_activity('PASSWORD_RESET_REQUESTED', 'Admin', admin.id,
                         f'Password reset requested for "{admin.username}"')

        # Always show the same message — don't reveal whether the email exists
        flash('If that email is registered, a password reset link has been sent.', 'info')
        return redirect(url_for('auth.login'))

    return render_template('forgot_password.html')


@auth.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    admin = verify_reset_token(token)
    if not admin:
        flash('That password reset link is invalid or has expired. Please request a new one.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if len(new_password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return render_template('reset_password.html', token=token)

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)

        admin.set_password(new_password)
        db.session.commit()
        log_activity('PASSWORD_RESET_COMPLETED', 'Admin', admin.id,
                     f'Password reset completed for "{admin.username}"')
        flash('Your password has been reset. Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html', token=token)


# ─── Two-Factor Authentication (Google Authenticator) ────────────────────────

@auth.route('/2fa/setup', methods=['GET', 'POST'])
@login_required
def two_factor_setup():
    """Generate a new TOTP secret and display the QR code for scanning."""
    import pyotp, qrcode, io, base64

    if request.method == 'POST':
        # User confirmed they scanned the QR — validate one code before enabling
        code = request.form.get('totp_code', '').strip().replace(' ', '')
        secret = session.get('_totp_setup_secret')

        if not secret:
            flash('Setup session expired. Please start again.', 'danger')
            return redirect(url_for('auth.two_factor_setup'))

        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            current_user.totp_secret = secret
            current_user.totp_enabled = True
            db.session.commit()
            session.pop('_totp_setup_secret', None)
            log_activity('2FA_ENABLED', 'Admin', current_user.id,
                         f'Admin "{current_user.username}" enabled 2FA')
            flash('Two-factor authentication has been enabled successfully!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid code. Please scan the QR again and retry.', 'danger')
            return redirect(url_for('auth.two_factor_setup'))

    # GET: generate (or reuse from session) a provisional secret
    secret = session.get('_totp_setup_secret') or pyotp.random_base32()
    session['_totp_setup_secret'] = secret

    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name='PhishGuard'
    )

    # Render QR code as inline base64 PNG
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('auth/two_factor_setup.html',
                           qr_b64=qr_b64,
                           secret=secret)


@auth.route('/2fa/disable', methods=['POST'])
@login_required
def two_factor_disable():
    """Disable 2FA after confirming password."""
    password = request.form.get('password', '')
    if not current_user.check_password(password):
        flash('Incorrect password. Two-factor authentication was NOT disabled.', 'danger')
        return redirect(url_for('main.dashboard'))

    current_user.totp_secret = None
    current_user.totp_enabled = False
    db.session.commit()
    log_activity('2FA_DISABLED', 'Admin', current_user.id,
                 f'Admin "{current_user.username}" disabled 2FA')
    flash('Two-factor authentication has been disabled.', 'warning')
    return redirect(url_for('main.dashboard'))




# ─── Settings / Change Password ──────────────────────────────────────────────

@main.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


@main.route('/settings/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password', '')
    new_password     = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_user.check_password(current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('main.settings'))

    if len(new_password) < 8:
        flash('New password must be at least 8 characters.', 'danger')
        return redirect(url_for('main.settings'))

    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('main.settings'))

    if new_password == current_password:
        flash('New password must be different from the current one.', 'warning')
        return redirect(url_for('main.settings'))

    current_user.set_password(new_password)
    db.session.commit()
    log_activity('PASSWORD_CHANGED', 'Admin', current_user.id,
                 f'Admin "{current_user.username}" changed their password')
    flash('Password updated successfully.', 'success')
    return redirect(url_for('main.settings'))

# ─── Dashboard ───────────────────────────────────────────────────────────────

@main.route('/')
@main.route('/dashboard')
@login_required
def dashboard():
    total_employees = Employee.query.filter_by(is_active=True).count()
    total_departments = Department.query.filter_by(is_active=True).count()
    total_uploads = UploadHistory.query.count()
    active_campaigns = Campaign.query.filter(Campaign.status.in_(['sending', 'scheduled'])).count()

    recent_campaigns = Campaign.query.order_by(
    Campaign.created_at.desc()
).limit(5).all()

    total_campaigns = Campaign.query.count()
    # Department distribution
    dept_data = db.session.query(
        Employee.department,
        func.count(Employee.id).label('count')
    ).filter(Employee.is_active == True).group_by(Employee.department).all()

    # Recent activity logs
    recent_logs = ActivityLog.query.order_by(
        ActivityLog.created_at.desc()
    ).limit(10).all()

    # Recent uploads
    recent_uploads = UploadHistory.query.order_by(
        UploadHistory.uploaded_at.desc()
    ).limit(5).all()

    # Top departments by employee count
    top_departments = Department.query.filter_by(is_active=True).all()
    top_departments = sorted(top_departments, key=lambda d: d.employee_count, reverse=True)[:5]
    recent_campaigns = Campaign.query.order_by(
    Campaign.created_at.desc()
).limit(5).all()

    total_campaigns = Campaign.query.count()

    # Campaign funnel data for bar chart
    all_campaigns = Campaign.query.order_by(Campaign.created_at.desc()).limit(8).all()
    funnel_data = []
    for c in all_campaigns:
        targets = c.targets
        total_t = len(targets)
        if total_t == 0:
            continue
        funnel_data.append({
            'name': c.name[:20],
            'sent': sum(1 for t in targets if t.email_sent_at),
            'opened': sum(1 for t in targets if t.email_opened_at),
            'clicked': sum(1 for t in targets if t.link_clicked_at),
            'submitted': sum(1 for t in targets if t.credentials_submitted_at),
        })

    return render_template(
    'dashboard.html',
    total_employees=total_employees,
    total_departments=total_departments,
    total_uploads=total_uploads,
    total_campaigns=total_campaigns,
    active_campaigns=active_campaigns,
    recent_campaigns=recent_campaigns,
    dept_data=json.dumps([
        {'name': d.department or 'Unknown',
         'count': d.count}
        for d in dept_data
    ]),
    funnel_data=json.dumps(funnel_data),
    recent_logs=recent_logs,
    recent_uploads=recent_uploads,
    top_departments=top_departments
)


# ─── Employee Routes ──────────────────────────────────────────────────────────

@main.route('/employees')
@login_required
def employees():
    page = request.args.get('page', 1, type=int)
    per_page = current_app.config['ITEMS_PER_PAGE']
    search = request.args.get('search', '').strip()
    dept_filter = request.args.get('department', '').strip()
    desig_filter = request.args.get('designation', '').strip()

    query = Employee.query.filter_by(is_active=True)

    if search:
        query = query.filter(or_(
            Employee.employee_name.ilike(f'%{search}%'),
            Employee.employee_id.ilike(f'%{search}%'),
            Employee.email.ilike(f'%{search}%'),
        ))
    if dept_filter:
        query = query.filter(Employee.department == dept_filter)
    if desig_filter:
        query = query.filter(Employee.designation == desig_filter)

    pagination = query.order_by(Employee.employee_name).paginate(
        page=page, per_page=per_page, error_out=False
    )

    departments = db.session.query(Employee.department).filter(
        Employee.is_active == True, Employee.department.isnot(None)
    ).distinct().order_by(Employee.department).all()
    departments = [d[0] for d in departments]

    designations = db.session.query(Employee.designation).filter(
        Employee.is_active == True, Employee.designation.isnot(None)
    ).distinct().order_by(Employee.designation).all()
    designations = [d[0] for d in designations]

    return render_template('employees/list.html',
                           employees=pagination.items,
                           pagination=pagination,
                           search=search,
                           dept_filter=dept_filter,
                           desig_filter=desig_filter,
                           departments=departments,
                           designations=designations)


@main.route('/employees/<int:emp_id>')
@login_required
def employee_detail(emp_id):
    emp = Employee.query.get_or_404(emp_id)
    return render_template('employees/detail.html', employee=emp)


@main.route('/employees/add', methods=['GET', 'POST'])
@login_required
def add_employee():
    departments = Department.query.filter_by(is_active=True).order_by(Department.name).all()

    if request.method == 'POST':
        employee_id = request.form.get('employee_id', '').strip()
        employee_name = request.form.get('employee_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        department = request.form.get('department', '').strip()
        designation = request.form.get('designation', '').strip()
        office_location = request.form.get('office_location', '').strip()

        errors = []
        existing_id_match = Employee.query.filter_by(employee_id=employee_id).first()
        existing_email_match = Employee.query.filter_by(email=email).first()

        if not employee_id:
            errors.append('Employee ID is required.')
        if not employee_name:
            errors.append('Employee name is required.')
        if not email:
            errors.append('Email is required.')
        if existing_id_match and existing_id_match.is_active:
            errors.append(f'Employee ID "{employee_id}" already exists.')
        if existing_email_match and existing_email_match.is_active and \
                (not existing_id_match or existing_email_match.id != existing_id_match.id):
            errors.append(f'Email "{email}" already exists.')

        if errors:
            for e in errors:
                flash(e, 'danger')
        elif existing_id_match and not existing_id_match.is_active:
            # Reactivate a previously-deleted employee instead of blocking re-add
            existing_id_match.employee_name = employee_name
            existing_id_match.email = email
            existing_id_match.department = department
            existing_id_match.designation = designation
            existing_id_match.office_location = office_location
            existing_id_match.is_active = True
            existing_id_match.updated_at = datetime.now(timezone.utc)
            db.session.commit()
            log_activity('EMPLOYEE_ADDED', 'Employee', existing_id_match.id,
                         f'Re-added (reactivated) employee {employee_name} ({employee_id})')
            flash(f'Employee {employee_name} re-added successfully.', 'success')
            return redirect(url_for('main.employees'))
        else:
            emp = Employee(
                employee_id=employee_id,
                employee_name=employee_name,
                email=email,
                department=department,
                designation=designation,
                office_location=office_location,
            )
            db.session.add(emp)
            db.session.commit()
            log_activity('EMPLOYEE_ADDED', 'Employee', emp.id,
                         f'Added employee {employee_name} ({employee_id})')
            flash(f'Employee {employee_name} added successfully.', 'success')
            return redirect(url_for('main.employees'))

    return render_template('employees/add.html', departments=departments)


@main.route('/employees/<int:emp_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_employee(emp_id):
    emp = Employee.query.get_or_404(emp_id)
    departments = Department.query.filter_by(is_active=True).order_by(Department.name).all()

    if request.method == 'POST':
        old_name = emp.employee_name
        emp.employee_name = request.form.get('employee_name', '').strip()
        emp.email = request.form.get('email', '').strip().lower()
        emp.department = request.form.get('department', '').strip()
        emp.designation = request.form.get('designation', '').strip()
        emp.office_location = request.form.get('office_location', '').strip()
        emp.updated_at = datetime.now(timezone.utc)

        # Check email uniqueness (excluding current employee)
        existing = Employee.query.filter(
            Employee.email == emp.email, Employee.id != emp.id
        ).first()
        if existing:
            flash(f'Email "{emp.email}" is already used by another employee.', 'danger')
            return render_template('employees/edit.html', employee=emp, departments=departments)

        db.session.commit()
        log_activity('EMPLOYEE_EDITED', 'Employee', emp.id,
                     f'Edited employee {old_name} → {emp.employee_name}')
        flash(f'Employee {emp.employee_name} updated successfully.', 'success')
        return redirect(url_for('main.employees'))

    return render_template('employees/edit.html', employee=emp, departments=departments)


@main.route('/employees/<int:emp_id>/delete', methods=['POST'])
@login_required
def delete_employee(emp_id):
    emp = Employee.query.get_or_404(emp_id)
    name = emp.employee_name
    eid = emp.employee_id
    emp.is_active = False  # soft delete
    db.session.commit()
    log_activity('EMPLOYEE_DELETED', 'Employee', emp_id,
                 f'Deleted employee {name} ({eid})')
    flash(f'Employee {name} removed from the directory.', 'success')
    return redirect(url_for('main.employees'))


# ─── CSV Upload ───────────────────────────────────────────────────────────────

@main.route('/employees/upload', methods=['GET', 'POST'])
@login_required
def upload_employees():
    if request.method == 'POST':
        if 'csv_file' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(request.url)

        file = request.files['csv_file']
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash('Only CSV files are allowed.', 'danger')
            return redirect(request.url)

        original_name = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex}_{original_name}"
        save_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_name)
        file.save(save_path)

        # Parse CSV
        try:
            df = pd.read_csv(save_path)
        except Exception as e:
            flash(f'Could not parse CSV: {str(e)}', 'danger')
            os.remove(save_path)
            return redirect(request.url)

        # Normalize column names
        df.columns = [c.strip().lower().replace(' ', '_') for c in df.columns]
        missing_cols = REQUIRED_CSV_COLUMNS - set(df.columns)
        if missing_cols:
            flash(f'Missing required columns: {", ".join(sorted(missing_cols))}', 'danger')
            os.remove(save_path)
            return redirect(request.url)

        upload_record = UploadHistory(
            admin_id=current_user.id,
            filename=unique_name,
            original_filename=original_name,
            total_rows=len(df),
            status='processing',
        )
        db.session.add(upload_record)
        db.session.commit()

        success_count = 0
        failed_count = 0
        duplicate_count = 0
        errors = []

        for idx, row in df.iterrows():
            row_num = idx + 2  # 1-based, offset for header

            emp_id = str(row.get('employee_id', '')).strip()
            emp_name = str(row.get('employee_name', '')).strip()
            email = str(row.get('email', '')).strip().lower()
            department = str(row.get('department', '')).strip()
            designation = str(row.get('designation', '')).strip()
            location = str(row.get('office_location', '')).strip()

            # Basic validation
            if not emp_id or emp_id == 'nan':
                errors.append({'row': row_num, 'error': 'Missing employee_id'})
                failed_count += 1
                continue
            if not emp_name or emp_name == 'nan':
                errors.append({'row': row_num, 'error': f'Row {row_num}: Missing employee_name'})
                failed_count += 1
                continue
            if not email or email == 'nan' or '@' not in email:
                errors.append({'row': row_num, 'error': f'Row {row_num}: Invalid email'})
                failed_count += 1
                continue

            # Duplicate check — only block on ACTIVE matches.
            # If the only match is a soft-deleted (is_active=False) record,
            # reactivate it with the fresh CSV data instead of rejecting the row.
            existing_by_id = Employee.query.filter_by(employee_id=emp_id).first()
            existing_by_email = Employee.query.filter_by(email=email).first()

            if existing_by_id and existing_by_id.is_active:
                errors.append({'row': row_num, 'error': f'Duplicate employee_id: {emp_id}'})
                duplicate_count += 1
                continue
            if existing_by_email and existing_by_email.is_active and \
                    (not existing_by_id or existing_by_email.id != existing_by_id.id):
                errors.append({'row': row_num, 'error': f'Duplicate email: {email}'})
                duplicate_count += 1
                continue

            if existing_by_id and not existing_by_id.is_active:
                # Reactivate previously-deleted employee with updated info
                existing_by_id.employee_name = emp_name
                existing_by_id.email = email
                existing_by_id.department = department if department != 'nan' else None
                existing_by_id.designation = designation if designation != 'nan' else None
                existing_by_id.office_location = location if location != 'nan' else None
                existing_by_id.is_active = True
                existing_by_id.updated_at = datetime.now(timezone.utc)
                success_count += 1
                continue

            emp = Employee(
                employee_id=emp_id,
                employee_name=emp_name,
                email=email,
                department=department if department != 'nan' else None,
                designation=designation if designation != 'nan' else None,
                office_location=location if location != 'nan' else None,
            )
            db.session.add(emp)
            success_count += 1

        db.session.commit()

        upload_record.successful_rows = success_count
        upload_record.failed_rows = failed_count
        upload_record.duplicate_rows = duplicate_count
        upload_record.error_details = json.dumps(errors[:100])  # cap stored errors
        upload_record.status = 'completed'
        db.session.commit()

        log_activity('CSV_UPLOAD', 'Upload', upload_record.id,
                     f'Uploaded {original_name}: {success_count} added, '
                     f'{duplicate_count} duplicates, {failed_count} errors')

        return render_template('employees/upload_result.html',
                               upload=upload_record,
                               errors=errors[:50],
                               success_count=success_count,
                               duplicate_count=duplicate_count,
                               failed_count=failed_count)

    return render_template('employees/upload.html')


# ─── Department Routes ────────────────────────────────────────────────────────

@main.route('/departments')
@login_required
def departments():
    depts = Department.query.filter_by(is_active=True).order_by(Department.name).all()
    return render_template('departments/list.html', departments=depts)


@main.route('/departments/add', methods=['GET', 'POST'])
@login_required
def add_department():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        code = request.form.get('code', '').strip().upper()
        description = request.form.get('description', '').strip()
        head_name = request.form.get('head_name', '').strip()

        if not name:
            flash('Department name is required.', 'danger')
            return redirect(request.url)
        if Department.query.filter_by(name=name).first():
            flash(f'Department "{name}" already exists.', 'danger')
            return redirect(request.url)

        dept = Department(name=name, code=code or None,
                          description=description, head_name=head_name)
        db.session.add(dept)
        db.session.commit()
        log_activity('DEPT_ADDED', 'Department', dept.id, f'Created department: {name}')
        flash(f'Department "{name}" created successfully.', 'success')
        return redirect(url_for('main.departments'))

    return render_template('departments/add.html')


@main.route('/departments/<int:dept_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_department(dept_id):
    dept = Department.query.get_or_404(dept_id)

    if request.method == 'POST':
        old_name = dept.name
        dept.name = request.form.get('name', '').strip()
        dept.code = request.form.get('code', '').strip().upper() or None
        dept.description = request.form.get('description', '').strip()
        dept.head_name = request.form.get('head_name', '').strip()
        dept.updated_at = datetime.now(timezone.utc)

        existing = Department.query.filter(
            Department.name == dept.name, Department.id != dept.id
        ).first()
        if existing:
            flash(f'Department name "{dept.name}" already exists.', 'danger')
            return render_template('departments/edit.html', department=dept)

        db.session.commit()
        log_activity('DEPT_EDITED', 'Department', dept.id,
                     f'Edited department {old_name} → {dept.name}')
        flash(f'Department "{dept.name}" updated.', 'success')
        return redirect(url_for('main.departments'))

    return render_template('departments/edit.html', department=dept)


@main.route('/departments/<int:dept_id>/delete', methods=['POST'])
@login_required
def delete_department(dept_id):
    dept = Department.query.get_or_404(dept_id)
    name = dept.name
    dept.is_active = False
    db.session.commit()
    log_activity('DEPT_DELETED', 'Department', dept_id, f'Deleted department: {name}')
    flash(f'Department "{name}" removed.', 'success')
    return redirect(url_for('main.departments'))


# ─── Activity Logs ────────────────────────────────────────────────────────────

@main.route('/activity-logs')
@login_required
def activity_logs():
    page = request.args.get('page', 1, type=int)
    action_filter = request.args.get('action', '').strip()

    query = ActivityLog.query
    if action_filter:
        query = query.filter(ActivityLog.action == action_filter)

    pagination = query.order_by(ActivityLog.created_at.desc()).paginate(
        page=page, per_page=50, error_out=False
    )

    action_types = db.session.query(ActivityLog.action).distinct().order_by(
        ActivityLog.action
    ).all()
    action_types = [a[0] for a in action_types]

    return render_template('activity_logs.html',
                           logs=pagination.items,
                           pagination=pagination,
                           action_filter=action_filter,
                           action_types=action_types)


# ─── API Endpoints (for future AJAX / campaign engine) ────────────────────────

@main.route('/api/employees/search')
@login_required
def api_search_employees():
    q = request.args.get('q', '').strip()
    if len(q) < 2:
        return jsonify([])
    results = Employee.query.filter(
        Employee.is_active == True,
        or_(
            Employee.employee_name.ilike(f'%{q}%'),
            Employee.employee_id.ilike(f'%{q}%'),
            Employee.email.ilike(f'%{q}%'),
        )
    ).limit(20).all()
    return jsonify([e.to_dict() for e in results])


@main.route('/api/stats/overview')
@login_required
def api_stats_overview():
    return jsonify({
        'total_employees': Employee.query.filter_by(is_active=True).count(),
        'total_departments': Department.query.filter_by(is_active=True).count(),
        'total_uploads': UploadHistory.query.count(),
        'recent_activity': ActivityLog.query.count(),
    })

@main.route('/templates')
@login_required
def email_templates():

    templates = EmailTemplate.query.order_by(
        EmailTemplate.created_at.desc()
    ).all()

    return render_template(
        'templates_mgmt/list.html',
        templates=templates
    )


@main.route('/templates/add', methods=['GET', 'POST'])
@login_required
def add_template():

    if request.method == 'POST':

        template = EmailTemplate(
            name=request.form.get('name'),
            subject=request.form.get('subject'),
            body_html=request.form.get('body'),
            category=request.form.get('category'),
            difficulty=int(request.form.get('difficulty', 1))
        )

        # Optional attachment: PDF or image, stored on disk like CSV uploads
        file = request.files.get('attachment')
        if file and file.filename:
            if not allowed_attachment_file(file.filename):
                flash('Attachment must be a PDF, PNG, JPG, JPEG, or GIF file.', 'danger')
                return render_template('templates_mgmt/add.html')

            original_name = secure_filename(file.filename)
            ext = original_name.rsplit('.', 1)[1].lower()
            stored_name = f'{uuid.uuid4().hex}.{ext}'
            save_path = os.path.join(current_app.config['TEMPLATE_ATTACHMENT_FOLDER'], stored_name)
            file.save(save_path)

            template.attachment_filename = stored_name
            template.attachment_original_name = original_name
            template.attachment_mimetype = file.mimetype

        db.session.add(template)
        db.session.commit()

        log_activity('TEMPLATE_ADDED', 'EmailTemplate', template.id,
                     f'Created template "{template.name}"')

        flash(
            'Template created successfully.',
            'success'
        )

        return redirect(
            url_for('main.email_templates')
        )

    return render_template(
        'templates_mgmt/add.html'
    )


@main.route('/templates/<int:template_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_template(template_id):
    template = EmailTemplate.query.get_or_404(template_id)

    if request.method == 'POST':
        template.name = request.form.get('name')
        template.subject = request.form.get('subject')
        template.body_html = request.form.get('body')
        template.category = request.form.get('category')
        template.difficulty = int(request.form.get('difficulty', 1))

        # Optional new attachment — replaces the old one if provided
        file = request.files.get('attachment')
        if file and file.filename:
            if not allowed_attachment_file(file.filename):
                flash('Attachment must be a PDF, PNG, JPG, JPEG, or GIF file.', 'danger')
                return render_template('templates_mgmt/edit.html', template=template)

            # Remove old attachment file from disk, if any
            if template.attachment_filename:
                old_path = os.path.join(
                    current_app.config['TEMPLATE_ATTACHMENT_FOLDER'],
                    template.attachment_filename
                )
                if os.path.exists(old_path):
                    os.remove(old_path)

            original_name = secure_filename(file.filename)
            ext = original_name.rsplit('.', 1)[1].lower()
            stored_name = f'{uuid.uuid4().hex}.{ext}'
            save_path = os.path.join(current_app.config['TEMPLATE_ATTACHMENT_FOLDER'], stored_name)
            file.save(save_path)

            template.attachment_filename = stored_name
            template.attachment_original_name = original_name
            template.attachment_mimetype = file.mimetype

        # Checkbox to remove the existing attachment without uploading a new one
        if request.form.get('remove_attachment') == 'on' and not (file and file.filename):
            if template.attachment_filename:
                old_path = os.path.join(
                    current_app.config['TEMPLATE_ATTACHMENT_FOLDER'],
                    template.attachment_filename
                )
                if os.path.exists(old_path):
                    os.remove(old_path)
            template.attachment_filename = None
            template.attachment_original_name = None
            template.attachment_mimetype = None

        db.session.commit()

        log_activity('TEMPLATE_EDITED', 'EmailTemplate', template.id,
                     f'Edited template "{template.name}"')

        flash('Template updated successfully.', 'success')
        return redirect(url_for('main.email_templates'))

    return render_template('templates_mgmt/edit.html', template=template)


@main.route('/templates/<int:template_id>/delete', methods=['POST'])
@login_required
def delete_template(template_id):
    template = EmailTemplate.query.get_or_404(template_id)

    if template.campaigns:
        flash(
            f'Cannot delete "{template.name}" — it is used by {len(template.campaigns)} campaign(s).',
            'danger'
        )
        return redirect(url_for('main.email_templates'))

    if template.attachment_filename:
        path = os.path.join(current_app.config['TEMPLATE_ATTACHMENT_FOLDER'], template.attachment_filename)
        if os.path.exists(path):
            os.remove(path)

    name = template.name
    db.session.delete(template)
    db.session.commit()

    log_activity('TEMPLATE_DELETED', 'EmailTemplate', template_id, f'Deleted template "{name}"')
    flash(f'Template "{name}" deleted.', 'success')
    return redirect(url_for('main.email_templates'))
@main.route('/campaigns')
@login_required
def campaigns():

    campaigns = Campaign.query.all()

    return render_template(
        'campaigns/list.html',
        campaigns=campaigns
    )


@main.route('/campaigns/<int:campaign_id>/delete', methods=['POST'])
@login_required
def delete_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    name = campaign.name
    CampaignTarget.query.filter_by(campaign_id=campaign_id).delete()
    db.session.delete(campaign)
    db.session.commit()
    log_activity('CAMPAIGN_DELETED', 'Campaign', campaign_id,
                 f'Deleted campaign {name}')
    flash(f'Campaign "{name}" deleted.', 'success')
    return redirect(url_for('main.campaigns'))


@main.route('/campaigns/add',
            methods=['GET', 'POST'])
@login_required
def add_campaign():

    templates = EmailTemplate.query.all()
    departments = Department.query.all()

    if request.method == 'POST':

        scheduled_at_raw = request.form.get('scheduled_at')  # 'YYYY-MM-DDTHH:MM' from <input type=datetime-local>, entered in IST
        scheduled_at = None
        status = 'draft'

        if scheduled_at_raw:
            try:
                # Interpret the entered time as IST, then convert to UTC for storage
                local_dt = datetime.fromisoformat(scheduled_at_raw).replace(tzinfo=IST)
                scheduled_at = local_dt.astimezone(timezone.utc)
                if scheduled_at > datetime.now(timezone.utc):
                    status = 'scheduled'
            except ValueError:
                flash('Invalid schedule date/time.', 'danger')
                return render_template('campaigns/add.html', templates=templates, departments=departments)

        campaign = Campaign(
            name=request.form.get('name'),
            template_id=request.form.get('template_id'),
            target_department=request.form.get(
                'target_department'
            ),
            scheduled_at=scheduled_at,
            status=status,
            created_by=current_user.id
        )

        db.session.add(campaign)
        db.session.commit()

        if status == 'scheduled':
            ist_display = scheduled_at.astimezone(IST)
            log_activity('CAMPAIGN_SCHEDULED', 'Campaign', campaign.id,
                         f'Campaign "{campaign.name}" scheduled for {ist_display} IST')
            flash(
                f'Campaign scheduled for {ist_display.strftime("%d %b %Y, %H:%M")} IST.',
                'success'
            )
        else:
            flash(
                'Campaign created successfully.',
                'success'
            )

        return redirect(
            url_for('main.campaigns')
        )

    return render_template(
        'campaigns/add.html',
        templates=templates,
        departments=departments
    )
@main.route('/reports')
@login_required
def reports():
    from models import PhishingSubmission

    all_campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()

    # ── Overall KPIs ──
    all_targets = CampaignTarget.query.all()
    total_emails_sent  = sum(1 for t in all_targets if t.email_sent_at)
    total_opened       = sum(1 for t in all_targets if t.email_opened_at)
    total_clicked      = sum(1 for t in all_targets if t.link_clicked_at)
    total_submitted    = sum(1 for t in all_targets if t.credentials_submitted_at)

    def pct(n, d): return round((n / d) * 100, 1) if d else 0
    overall_open_rate   = pct(total_opened,    total_emails_sent)
    overall_click_rate  = pct(total_clicked,   total_emails_sent)
    overall_submit_rate = pct(total_submitted, total_emails_sent)
    safe_rate           = pct(total_emails_sent - total_clicked, total_emails_sent)

    # ── Funnel data per campaign (for bar chart) ──
    funnel_data = []
    for c in all_campaigns:
        targets = c.targets
        if not targets:
            continue
        funnel_data.append({
            'name':      c.name[:22],
            'sent':      sum(1 for t in targets if t.email_sent_at),
            'opened':    sum(1 for t in targets if t.email_opened_at),
            'clicked':   sum(1 for t in targets if t.link_clicked_at),
            'submitted': sum(1 for t in targets if t.credentials_submitted_at),
        })

    # ── Dept employee distribution (for doughnut) ──
    dept_counts = db.session.query(
        Employee.department, func.count(Employee.id).label('count')
    ).filter(Employee.is_active == True).group_by(Employee.department).all()
    dept_data = json.dumps([{'name': d.department or 'Unknown', 'count': d.count} for d in dept_counts])

    # ── Click rate by department ──
    dept_risk = []
    for d in dept_counts:
        dept_name = d.department or 'Unknown'
        emp_ids = [e.id for e in Employee.query.filter_by(department=d.department, is_active=True).all()]
        if not emp_ids:
            continue
        dept_targets = CampaignTarget.query.filter(CampaignTarget.employee_id.in_(emp_ids)).all()
        sent    = sum(1 for t in dept_targets if t.email_sent_at)
        clicked = sum(1 for t in dept_targets if t.link_clicked_at)
        dept_risk.append({'dept': dept_name, 'click_rate': pct(clicked, sent)})
    dept_risk.sort(key=lambda x: x['click_rate'], reverse=True)

    # ── High risk employees ──
    high_risk_employees = Employee.query.filter(
        Employee.is_active == True, Employee.risk_score > 0
    ).order_by(Employee.risk_score.desc()).limit(10).all()

    return render_template(
        'reports/dashboard.html',
        total_campaigns=Campaign.query.count(),
        total_emails_sent=total_emails_sent,
        overall_open_rate=overall_open_rate,
        overall_click_rate=overall_click_rate,
        overall_submit_rate=overall_submit_rate,
        safe_rate=safe_rate,
        funnel_data=json.dumps(funnel_data),
        dept_data=dept_data,
        dept_risk=dept_risk,
        high_risk_employees=high_risk_employees,
        all_campaigns=all_campaigns,
    )
from datetime import datetime, timezone
from models import PhishingSubmission

# ─── Email Open Pixel Tracker ────────────────────────────────────────────────

@main.route('/track/<token>')
def track_email(token):
    """1x1 invisible pixel — records when email was opened."""
    target = CampaignTarget.query.filter_by(tracking_token=token).first()
    if target and not target.email_opened_at:
        target.email_opened_at = datetime.now(timezone.utc)
        db.session.commit()
    # Return a 1x1 transparent GIF
    pixel = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
    from flask import Response
    return Response(pixel, mimetype='image/gif')


# ─── Phishing Link Click → Fake Login Page ───────────────────────────────────

@main.route('/click/<token>', methods=['GET', 'POST'])
def click_track(token):
    """When employee clicks phishing link: show fake login, then training page."""
    target = CampaignTarget.query.filter_by(tracking_token=token).first_or_404()

    if request.method == 'POST':
        # Employee submitted the fake login form — record it
        submitted_email = request.form.get('username', '') or request.form.get('email', '')

        if not target.credentials_submitted_at:
            target.credentials_submitted_at = datetime.now(timezone.utc)

            submission = PhishingSubmission(
                campaign_target_id=target.id,
                submitted_email=submitted_email,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string[:255] if request.user_agent else None,
            )
            db.session.add(submission)

            # Update employee risk score
            emp = target.employee
            if emp:
                emp.risk_score = min(100.0, emp.risk_score + 25.0)
                emp.last_simulation = datetime.now(timezone.utc)

            db.session.commit()

        # Redirect to training/awareness page
        return redirect(url_for('main.training_page', token=token))

    # GET — record click, show fake login
    if not target.link_clicked_at:
        target.link_clicked_at = datetime.now(timezone.utc)
        db.session.commit()

    return render_template('tracking/fake_login.html', token=token)


@main.route('/training/<token>')
def training_page(token):
    """Security awareness training page shown after employee falls for phishing."""
    target = CampaignTarget.query.filter_by(tracking_token=token).first_or_404()
    return render_template('tracking/training.html', employee=target.employee)


# ─── Campaign Launch ──────────────────────────────────────────────────────────

@main.route('/campaigns/<int:campaign_id>/launch', methods=['POST'])
@login_required
def launch_campaign(campaign_id):
    """Generate tracking tokens, then send emails in the background (real-time, non-blocking)."""
    import secrets
    from flask import current_app
    from mail_service import send_campaign_async

    campaign = Campaign.query.get_or_404(campaign_id)

    # Get employees for target department
    if campaign.target_department and campaign.target_department != 'ALL':
        employees = Employee.query.filter_by(
            department=campaign.target_department, is_active=True
        ).all()
    else:
        employees = Employee.query.filter_by(is_active=True).all()

    if not employees:
        flash('No active employees found in the target department.', 'warning')
        return redirect(url_for('main.campaign_detail', campaign_id=campaign_id))

    created = 0
    for emp in employees:
        # Skip if already targeted
        existing = CampaignTarget.query.filter_by(
            campaign_id=campaign.id, employee_id=emp.id
        ).first()
        if not existing:
            token = secrets.token_urlsafe(32)
            ct = CampaignTarget(
                campaign_id=campaign.id,
                employee_id=emp.id,
                tracking_token=token
            )
            db.session.add(ct)
            created += 1

    campaign.status = 'sending'
    db.session.commit()

    # Fire emails in a background thread — request returns immediately,
    # campaign detail page polls /api/campaigns/<id>/status for live progress
    send_campaign_async(current_app._get_current_object(), campaign.id)

    log_activity('CAMPAIGN_LAUNCHED', 'Campaign', campaign.id,
                 f'Campaign "{campaign.name}" launched — {created} targets, sending in background')
    flash(f'Campaign launched! Sending to {len(employees)} employees now…', 'success')

    return redirect(url_for('main.campaign_detail', campaign_id=campaign_id))


@main.route('/api/campaigns/<int:campaign_id>/status')
@login_required
def campaign_send_status(campaign_id):
    """Live polling endpoint: how many emails have gone out so far."""
    campaign = Campaign.query.get_or_404(campaign_id)
    total = len(campaign.targets)
    sent = sum(1 for t in campaign.targets if t.email_sent_at)
    return jsonify({
        'status': campaign.status,
        'total': total,
        'sent': sent,
        'done': campaign.status != 'sending'
    })


# ─── Campaign Calendar ────────────────────────────────────────────────────────



# ─── Serve Template Attachments ──────────────────────────────────────────────

@main.route('/templates/attachment/<filename>')
@login_required
def serve_attachment(filename):
    """Serve a stored template attachment (PDF / image) for preview or download."""
    from flask import send_from_directory
    folder = current_app.config['TEMPLATE_ATTACHMENT_FOLDER']
    return send_from_directory(folder, filename)

@main.route('/campaigns/calendar')
@login_required
def campaign_calendar():
    """Calendar view showing scheduled + sent campaign emails."""
    return render_template('campaigns/calendar.html')


@main.route('/api/campaigns/calendar-events')
@login_required
def campaign_calendar_events():
    """JSON feed of campaign events for the FullCalendar widget."""
    campaigns = Campaign.query.filter(
        db.or_(Campaign.scheduled_at.isnot(None), Campaign.sent_at.isnot(None))
    ).all()

    events = []
    for c in campaigns:
        if c.status == 'scheduled' and c.scheduled_at:
            events.append({
                'title': f'📅 {c.name} (scheduled)',
                'start': c.scheduled_at.isoformat(),
                'color': '#ffc107',
                'url': url_for('main.campaign_detail', campaign_id=c.id)
            })
        if c.sent_at:
            events.append({
                'title': f'✅ {c.name} (sent)',
                'start': c.sent_at.isoformat(),
                'color': '#23c55e',
                'url': url_for('main.campaign_detail', campaign_id=c.id)
            })

    return jsonify(events)


# ─── Campaign Detail + Analytics ─────────────────────────────────────────────

@main.route('/campaigns/<int:campaign_id>')
@login_required
def campaign_detail(campaign_id):
    """Per-campaign analytics: who clicked, who submitted, who didn't fall for it."""
    campaign = Campaign.query.get_or_404(campaign_id)
    targets = CampaignTarget.query.filter_by(campaign_id=campaign_id).all()

    total = len(targets)
    opened = sum(1 for t in targets if t.email_opened_at)
    clicked = sum(1 for t in targets if t.link_clicked_at)
    submitted = sum(1 for t in targets if t.credentials_submitted_at)
    safe = total - clicked

    # Build per-employee rows
    rows = []
    for t in targets:
        rows.append({
            'target': t,
            'employee': t.employee,
            'status': t.status,
            'phishing_link': url_for('main.click_track', token=t.tracking_token, _external=True),
        })

    return render_template('campaigns/detail.html',
                           campaign=campaign,
                           rows=rows,
                           total=total,
                           opened=opened,
                           clicked=clicked,
                           submitted=submitted,
                           safe=safe)