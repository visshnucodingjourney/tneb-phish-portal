import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'phishguard-dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f"sqlite:///{os.path.join(BASE_DIR, 'database', 'phishguard.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    TEMPLATE_ATTACHMENT_FOLDER = os.path.join(BASE_DIR, 'uploads', 'template_attachments')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    ALLOWED_EXTENSIONS = {'csv'}
    ALLOWED_ATTACHMENT_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Base URL used by mail_service to build tracking/click links in emails.
    # Change this to your real domain if deployed (e.g. https://phishguard.yourcompany.com)
    APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://127.0.0.1:5000')

    # SMTP settings (used by Flask-Mail to actually send campaign emails)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1']
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() in ['true', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = MAIL_USERNAME

    # Scheduler: how often (seconds) the background job checks for due campaigns
    SCHEDULER_API_ENABLED = False
    SCHEDULER_POLL_SECONDS = int(os.environ.get('SCHEDULER_POLL_SECONDS') or 60)

    CAMPAIGN_TRACKING_DOMAIN = os.environ.get('CAMPAIGN_TRACKING_DOMAIN')
    DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'phishing-sim@company.com')

    ITEMS_PER_PAGE = 25


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}