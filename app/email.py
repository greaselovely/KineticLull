"""Email integration via Resend for one-time file sharing."""

import logging
from .models import AppSettings

logger = logging.getLogger(__name__)


def _get_resend():
    """Return configured resend module, or None if not configured."""
    app_settings = AppSettings.load()
    if not app_settings.resend_api_key or not app_settings.resend_from_email:
        logger.error("Resend not configured. Set API key and from email in Settings.")
        return None, None
    import resend
    resend.api_key = app_settings.resend_api_key
    if app_settings.resend_from_name:
        from_address = f'{app_settings.resend_from_name} <{app_settings.resend_from_email}>'
    else:
        from_address = app_settings.resend_from_email
    return resend, from_address


def send_file_shared_email(recipient_email, filename, share_url, sender_name):
    """Email #1: Sent on upload — tells the recipient a file is waiting for them."""
    resend, from_email = _get_resend()
    if not resend:
        return False

    try:
        resend.Emails.send({
            "from": from_email,
            "to": [recipient_email],
            "subject": f"{sender_name} shared a file with you",
            "html": f"""
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="color: #1a1d21;">File Shared With You</h2>
                    <p><strong>{sender_name}</strong> has shared a file with you: <strong>{filename}</strong></p>
                    <p>Click the link below to download it. You will receive a verification code when you access the link.</p>
                    <div style="margin: 24px 0;">
                        <a href="{share_url}" style="background: #1a1d21; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600;">Download File</a>
                    </div>
                    <p style="color: #6c757d; font-size: 0.85rem;">If you were not expecting this file, you can ignore this email.</p>
                </div>
            """,
        })
        return True
    except Exception as e:
        logger.error(f"Failed to send file shared email to {recipient_email}: {e}")
        return False


def send_otp_email(recipient_email, otp, noun='file'):
    """Email #2: Sent when the recipient clicks the link — contains only the OTP.

    ``noun`` lets the shared OTP copy serve both files and secrets.
    """
    resend, from_email = _get_resend()
    if not resend:
        return False

    try:
        resend.Emails.send({
            "from": from_email,
            "to": [recipient_email],
            "subject": f"Your {noun} verification code",
            "html": f"""
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="color: #1a1d21;">Verification Code</h2>
                    <p>Enter this code to access your {noun}:</p>
                    <div style="background: #f5f6fa; padding: 16px; border-radius: 8px; text-align: center; margin: 16px 0;">
                        <span style="font-size: 2rem; font-weight: bold; letter-spacing: 8px; color: #1a1d21;">{otp}</span>
                    </div>
                    <p style="color: #6c757d; font-size: 0.85rem;">This code expires in 5 minutes. If you did not request this, ignore this email.</p>
                </div>
            """,
        })
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {recipient_email}: {e}")
        return False


def send_access_notification(uploader_email, recipient_email, item_label, noun='file', verb='downloaded'):
    """Email #3: Sent to the owner when the item is accessed.

    ``noun``/``verb`` let the shared copy serve both files ('downloaded') and
    secrets ('revealed').
    """
    resend, from_email = _get_resend()
    if not resend:
        return False

    try:
        resend.Emails.send({
            "from": from_email,
            "to": [uploader_email],
            "subject": f"{noun.capitalize()} accessed: {item_label}",
            "html": f"""
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="color: #1a1d21;">{noun.capitalize()} Access Notification</h2>
                    <p>Your shared {noun} <strong>{item_label}</strong> was {verb} by <strong>{recipient_email}</strong>.</p>
                    <p>The link has been burned and the {noun} has been deleted.</p>
                </div>
            """,
        })
        return True
    except Exception as e:
        logger.error(f"Failed to send access notification to {uploader_email}: {e}")
        return False


def send_secret_shared_email(recipient_email, label, share_url, sender_name):
    """Sent on create (if enabled) — tells the recipient a secret is waiting for them."""
    resend, from_email = _get_resend()
    if not resend:
        return False

    try:
        resend.Emails.send({
            "from": from_email,
            "to": [recipient_email],
            "subject": f"{sender_name} shared a secret with you",
            "html": f"""
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="color: #1a1d21;">A Secret Was Shared With You</h2>
                    <p><strong>{sender_name}</strong> has shared a secret with you: <strong>{label}</strong></p>
                    <p>Click the link below to reveal it. You will receive a verification code when you access the link. The secret can be viewed only once.</p>
                    <div style="margin: 24px 0;">
                        <a href="{share_url}" style="background: #1a1d21; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600;">Reveal Secret</a>
                    </div>
                    <p style="color: #6c757d; font-size: 0.85rem;">If you were not expecting this secret, you can ignore this email.</p>
                </div>
            """,
        })
        return True
    except Exception as e:
        logger.error(f"Failed to send secret shared email to {recipient_email}: {e}")
        return False
