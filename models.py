from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class Admin(UserMixin, db.Model):
    __tablename__ = 'admins'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(120))
    role = db.Column(db.String(32), default='admin')
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)

    activity_logs = db.relationship('ActivityLog', backref='admin', lazy='dynamic')
    upload_histories = db.relationship('UploadHistory', backref='admin', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<Admin {self.username}>'


class Department(db.Model):
    __tablename__ = 'departments'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    code = db.Column(db.String(20), unique=True)
    description = db.Column(db.Text)
    head_name = db.Column(db.String(120))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    employees = db.relationship('Employee', backref='department_obj', lazy='dynamic')

    @property
    def employee_count(self):
        return Employee.query.filter(
            Employee.department == self.name,
            Employee.is_active == True
        ).count()

    def __repr__(self):
        return f'<Department {self.name}>'


class Employee(db.Model):
    __tablename__ = 'employees'

    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    employee_name = db.Column(db.String(120), nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    department = db.Column(db.String(100), index=True)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=True)
    designation = db.Column(db.String(100), index=True)
    office_location = db.Column(db.String(120))
    phone = db.Column(db.String(30))
    is_active = db.Column(db.Boolean, default=True)
    risk_score = db.Column(db.Float, default=0.0)
    last_simulation = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'employee_id': self.employee_id,
            'employee_name': self.employee_name,
            'email': self.email,
            'department': self.department,
            'designation': self.designation,
            'office_location': self.office_location,
            'risk_score': self.risk_score,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d') if self.created_at else None,
        }

    def __repr__(self):
        return f'<Employee {self.employee_id}: {self.employee_name}>'


class UploadHistory(db.Model):
    __tablename__ = 'upload_histories'

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255))
    total_rows = db.Column(db.Integer, default=0)
    successful_rows = db.Column(db.Integer, default=0)
    failed_rows = db.Column(db.Integer, default=0)
    duplicate_rows = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='processing')
    error_details = db.Column(db.Text)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<UploadHistory {self.filename} by admin {self.admin_id}>'


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'

    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    entity_type = db.Column(db.String(32))
    entity_id = db.Column(db.String(50))
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f'<ActivityLog {self.action} at {self.created_at}>'


class EmailTemplate(db.Model):
    __tablename__ = 'email_templates'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    body_html = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))
    difficulty = db.Column(db.Integer, default=1)
    attachment_filename = db.Column(db.String(255))
    attachment_original_name = db.Column(db.String(255))
    attachment_mimetype = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<EmailTemplate {self.name}>'


class Campaign(db.Model):
    __tablename__ = 'campaigns'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    template_id = db.Column(db.Integer, db.ForeignKey('email_templates.id'))
    template = db.relationship('EmailTemplate', backref='campaigns')
    target_department = db.Column(db.String(100))
    status = db.Column(db.String(20), default='draft')
    scheduled_at = db.Column(db.DateTime)
    sent_at = db.Column(db.DateTime)
    created_by = db.Column(db.Integer, db.ForeignKey('admins.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # CASCADE: deleting a Campaign deletes its CampaignTargets automatically
    targets = db.relationship('CampaignTarget', backref='campaign',
                              cascade='all, delete-orphan', lazy='select')

    @property
    def total_targets(self):
        return len(self.targets)

    @property
    def open_rate(self):
        total = len(self.targets)
        if total == 0:
            return 0
        opened = sum(1 for t in self.targets if t.email_opened_at)
        return round((opened / total) * 100, 1)

    @property
    def click_rate(self):
        total = len(self.targets)
        if total == 0:
            return 0
        clicked = sum(1 for t in self.targets if t.link_clicked_at)
        return round((clicked / total) * 100, 1)

    @property
    def submit_rate(self):
        total = len(self.targets)
        if total == 0:
            return 0
        submitted = sum(1 for t in self.targets if t.credentials_submitted_at)
        return round((submitted / total) * 100, 1)


class CampaignTarget(db.Model):
    __tablename__ = 'campaign_targets'

    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id', ondelete='CASCADE'), nullable=False)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    tracking_token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email_sent_at = db.Column(db.DateTime)
    email_opened_at = db.Column(db.DateTime)
    link_clicked_at = db.Column(db.DateTime)
    credentials_submitted_at = db.Column(db.DateTime)
    reported_at = db.Column(db.DateTime)

    # CASCADE: deleting a CampaignTarget deletes its PhishingSubmissions
    submissions = db.relationship('PhishingSubmission', backref='target',
                                  cascade='all, delete-orphan', lazy='select')
    employee = db.relationship('Employee', backref='campaign_targets')

    @property
    def status(self):
        if self.credentials_submitted_at:
            return 'submitted'
        if self.link_clicked_at:
            return 'clicked'
        if self.email_opened_at:
            return 'opened'
        if self.email_sent_at:
            return 'sent'
        return 'pending'

    def __repr__(self):
        return f'<CampaignTarget campaign={self.campaign_id} employee={self.employee_id}>'


class PhishingSubmission(db.Model):
    __tablename__ = 'phishing_submissions'

    id = db.Column(db.Integer, primary_key=True)
    campaign_target_id = db.Column(db.Integer, db.ForeignKey('campaign_targets.id', ondelete='CASCADE'), nullable=False)
    submitted_email = db.Column(db.String(120))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    submitted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<PhishingSubmission target={self.campaign_target_id}>'