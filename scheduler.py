"""
scheduler.py
─────────────
Flask-APScheduler job that runs inside the app process. Every
SCHEDULER_POLL_SECONDS it checks for campaigns with status='scheduled'
whose scheduled_at time has passed, and sends them.
"""

import secrets
from datetime import datetime, timezone
from flask_apscheduler import APScheduler

scheduler = APScheduler()


def init_scheduler(app):
    scheduler.init_app(app)
    scheduler.start()

    poll_seconds = app.config.get('SCHEDULER_POLL_SECONDS', 60)

    @scheduler.task('interval', id='send_scheduled_campaigns',
                     seconds=poll_seconds, misfire_grace_time=300,
                     max_instances=1, coalesce=True)
    def send_scheduled_campaigns():
        with app.app_context():
            from models import db, Campaign, Employee, CampaignTarget
            from mail_service import send_campaign_now

            now = datetime.now(timezone.utc)
            due_campaigns = Campaign.query.filter(
                Campaign.status == 'scheduled',
                Campaign.scheduled_at <= now
            ).all()

            for campaign in due_campaigns:
                # Mark as sending immediately so duplicate runs skip it
                campaign.status = 'sending'
                db.session.commit()

                # ── Create CampaignTarget rows if not already done ──
                if campaign.target_department and campaign.target_department != 'ALL':
                    employees = Employee.query.filter_by(
                        department=campaign.target_department, is_active=True
                    ).all()
                else:
                    employees = Employee.query.filter_by(is_active=True).all()

                for emp in employees:
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

                db.session.commit()

                # ── Now send ──
                try:
                    sent, failed = send_campaign_now(campaign)
                    app.logger.info(
                        f'[PhishGuard] Scheduled campaign "{campaign.name}" fired: '
                        f'{sent} sent, {failed} failed'
                    )
                except Exception as exc:
                    import traceback
                    traceback.print_exc()
                    app.logger.error(
                        f'[PhishGuard] Scheduler failed for campaign "{campaign.name}": {exc}'
                    )
                    campaign.status = 'scheduled'  # reset so it retries next poll
                    db.session.commit()