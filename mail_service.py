"""
mail_service.py
────────────────
Builds and sends the actual simulation emails to CampaignTarget records.
Uses Flask-Mail (SMTP) — config comes from MAIL_SERVER / MAIL_USERNAME /
MAIL_PASSWORD / MAIL_DEFAULT_SENDER in config.py / environment variables.
"""

import os
import traceback
from flask import current_app
from flask_mail import Mail, Message

mail = Mail()


def _build_body(target, raw_html, base_url):
    """
    Inject the tracking pixel + rewrite the click-through link inside the
    template HTML. Uses base_url instead of url_for() so this works from
    background threads (scheduler / async send) with no active request.
    """
    token = target.tracking_token
    click_url = f"{base_url}/click/{token}"
    pixel_url = f"{base_url}/track/{token}"

    body = raw_html.replace('{{CLICK_LINK}}', click_url)
    if click_url not in body:
        body += f'<p><a href="{click_url}">Click here</a></p>'

    # Invisible tracking pixel
    body += f'<img src="{pixel_url}" width="1" height="1" style="display:none;">'
    return body


def send_campaign_email(target, template, recipient_email, base_url):
    """
    Send one simulation email for a given CampaignTarget + EmailTemplate.
    Returns True on success, False (and logs the error) on failure.
    """
    try:
        subject = template.subject
        html_body = _build_body(target, template.body_html, base_url)

        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            html=html_body,
            sender=current_app.config.get('MAIL_DEFAULT_SENDER'),
        )

        if template.attachment_filename:
            attach_path = os.path.join(
                current_app.config['TEMPLATE_ATTACHMENT_FOLDER'],
                template.attachment_filename
            )
            if os.path.exists(attach_path):
                with open(attach_path, 'rb') as f:
                    msg.attach(
                        filename=template.attachment_original_name or template.attachment_filename,
                        content_type=template.attachment_mimetype or 'application/octet-stream',
                        data=f.read()
                    )

        mail.send(msg)
        return True

    except Exception as exc:
        traceback.print_exc()
        current_app.logger.error(f'[PhishGuard] Failed to send to {recipient_email}: {exc}')
        return False


def send_campaign_now(campaign):
    """
    Send emails to every CampaignTarget belonging to a campaign that hasn't
    been sent yet. Used both by the manual "Launch" button and by the
    scheduler when a scheduled_at time comes due.
    """
    from models import db
    from datetime import datetime, timezone

    template = campaign.template
    if template is None:
        return 0, 0

    # Build base URL from config — works in background threads with no active request
    base_url = current_app.config.get('APP_BASE_URL', 'http://127.0.0.1:5000')

    sent_count, failed_count = 0, 0
    for target in campaign.targets:
        if target.email_sent_at:
            continue  # already sent

        try:
            ok = send_campaign_email(target, template, target.employee.email, base_url)
        except Exception as exc:
            traceback.print_exc()
            current_app.logger.error(
                f'[PhishGuard] Exception sending to {target.employee.email}: {exc}'
            )
            ok = False

        if ok:
            target.email_sent_at = datetime.now(timezone.utc)
            sent_count += 1
        else:
            failed_count += 1

        db.session.commit()  # commit per-email so progress is visible live

    campaign.status = 'sent'
    campaign.sent_at = datetime.now(timezone.utc)
    db.session.commit()
    return sent_count, failed_count


def send_campaign_async(app, campaign_id):
    """
    Fire the actual sending in a background thread so the web request
    returns instantly. Campaign status is set to 'sending' immediately,
    then flips to 'sent' when done (or back to 'active' on failure).
    """
    import threading

    def _worker():
        with app.app_context():
            from models import db, Campaign
            campaign = Campaign.query.get(campaign_id)
            if not campaign:
                return
            try:
                send_campaign_now(campaign)
            except Exception as exc:
                traceback.print_exc()
                app.logger.error(f'[PhishGuard] Async send failed for campaign {campaign_id}: {exc}')
                campaign.status = 'active'
                db.session.commit()

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()


# ─── Password Reset Email ─────────────────────────────────────────────────────

def send_password_reset_email(admin, reset_url):
    """
    Send a password-reset link to an admin. Used by the forgot-password flow.
    The caller always shows the same generic "if that email exists, a link
    was sent" message regardless of outcome, so we don't leak which emails
    are registered.
    """
    try:
        html_body = f"""
            <p>Hello {admin.full_name or admin.username},</p>
            <p>We received a request to reset your PhishGuard admin password.
               Click the link below to set a new password. This link expires in 30 minutes.</p>
            <p><a href="{reset_url}">Reset your password</a></p>
            <p>If you didn't request this, you can safely ignore this email.</p>
        """
        msg = Message(
            subject='PhishGuard — Password Reset Request',
            recipients=[admin.email],
            html=html_body,
            sender=current_app.config.get('MAIL_DEFAULT_SENDER'),
        )
        mail.send(msg)
        return True
    except Exception as exc:
        traceback.print_exc()
        current_app.logger.error(f'[PhishGuard] Failed to send reset email to {admin.email}: {exc}')
        return False