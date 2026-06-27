import os
from flask import Flask, redirect, url_for
from flask_login import LoginManager

from config import config
from models import db, Admin, PhishingSubmission
from mail_service import mail
from scheduler import init_scheduler


def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Ensure required directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['TEMPLATE_ATTACHMENT_FOLDER'], exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), 'database'), exist_ok=True)

    # Init extensions
    db.init_app(app)
    mail.init_app(app)


    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id):
        return Admin.query.get(int(user_id))

    # Register blueprints
    from routes import main, auth
    app.register_blueprint(auth)
    app.register_blueprint(main)

    # Future blueprints (register here when modules are built)
    # from campaigns.routes import campaigns_bp
    # app.register_blueprint(campaigns_bp)
    # from tracking.routes import tracking_bp
    # app.register_blueprint(tracking_bp)
    # from reporting.routes import reporting_bp
    # app.register_blueprint(reporting_bp)

    # Create DB tables and seed default admin on first run
    with app.app_context():
        db.create_all()
        _seed_defaults()

    # Start the background scheduler that fires scheduled campaigns
    # (with the debug reloader, Flask spawns a parent + child process —
    # only start the scheduler in the actual running process)
    skip_for_reloader = app.debug and os.environ.get('WERKZEUG_RUN_MAIN') != 'true'
    if not app.config.get('TESTING') and not skip_for_reloader:
        init_scheduler(app)

    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        from flask import render_template
        return render_template('errors/500.html'), 500

    return app


def _seed_defaults():
    """Create default admin and sample departments on fresh install."""
    from models import Admin, Department

    if not Admin.query.first():
        admin = Admin(
            username='admin',
            email='admin@phishguard.local',
            full_name='Platform Administrator',
            role='superadmin',
        )
        admin.set_password('Admin@123')
        db.session.add(admin)

        # Seed a handful of sample departments
        sample_depts = [
            Department(name='Information Technology', code='IT'),
            Department(name='Human Resources', code='HR'),
            Department(name='Finance & Accounts', code='FIN'),
            Department(name='Operations', code='OPS'),
            Department(name='Sales & Marketing', code='SAL'),
        ]
        db.session.add_all(sample_depts)
        db.session.commit()
        print('[PhishGuard] Default admin created — username: admin / password: Admin@123')


if __name__ == '__main__':
    app = create_app('development')
    app.run(debug=True, host='0.0.0.0', port=5000)
    print("MAIL_DEFAULT_SENDER =", app.config.get("MAIL_DEFAULT_SENDER"))