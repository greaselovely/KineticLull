"""Email integration via Resend for OTP delivery."""

import logging
from .models import AppSettings

logger = logging.getLogger(__name__)


def send_otp_email(recipient_email, otp, filename):
    """Send an OTP code to the recipient for file download verification."""
    app_settings = AppSettings.load()

    if not app_settings.resend_api_key or not app_settings.resend_from_email:
        logger.error("Resend not configured. Set API key and from email in Settings.")
        return False

    try:
        import resend
        resend.api_key = app_settings.resend_api_key

        resend.Emails.send({
            "from": app_settings.resend_from_email,
            "to": [recipient_email],
            "subject": "Your file download verification code",
            "html": f"""
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="color: #1a1d21;">KineticLull File Download</h2>
                    <p>Someone has shared a file with you: <strong>{filename}</strong></p>
                    <p>Your verification code is:</p>
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


def send_access_notification(uploader_email, recipient_email, filename):
    """Notify the uploader that their file link was accessed."""
    app_settings = AppSettings.load()

    if not app_settings.resend_api_key or not app_settings.resend_from_email:
        return False

    try:
        import resend
        resend.api_key = app_settings.resend_api_key

        resend.Emails.send({
            "from": app_settings.resend_from_email,
            "to": [uploader_email],
            "subject": f"File accessed: {filename}",
            "html": f"""
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="color: #1a1d21;">KineticLull File Access Notification</h2>
                    <p>Your shared file <strong>{filename}</strong> was accessed by <strong>{recipient_email}</strong>.</p>
                    <p>The file link has been burned and the file has been deleted.</p>
                </div>
            """,
        })
        return True
    except Exception as e:
        logger.error(f"Failed to send access notification to {uploader_email}: {e}")
        return False
