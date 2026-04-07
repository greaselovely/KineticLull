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


def send_otp_email(recipient_email, otp):
    """Email #2: Sent when the recipient clicks the download link — contains only the OTP."""
    resend, from_email = _get_resend()
    if not resend:
        return False

    try:
        resend.Emails.send({
            "from": from_email,
            "to": [recipient_email],
            "subject": "Your file download verification code",
            "html": f"""
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="color: #1a1d21;">Verification Code</h2>
                    <p>Enter this code to download your file:</p>
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
    """Email #3: Sent to the uploader when the file is downloaded."""
    resend, from_email = _get_resend()
    if not resend:
        return False

    try:
        resend.Emails.send({
            "from": from_email,
            "to": [uploader_email],
            "subject": f"File accessed: {filename}",
            "html": f"""
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="color: #1a1d21;">File Access Notification</h2>
                    <p>Your shared file <strong>{filename}</strong> was downloaded by <strong>{recipient_email}</strong>.</p>
                    <p>The link has been burned and the file has been deleted.</p>
                </div>
            """,
        })
        return True
    except Exception as e:
        logger.error(f"Failed to send access notification to {uploader_email}: {e}")
        return False
