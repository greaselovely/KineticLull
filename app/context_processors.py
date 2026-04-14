# context_processors.py
import hashlib
from .models import InboxEntry, AppSettings, ActivityLog, ExtDynLists


def inbox_count(request):
    if request.user.is_authenticated:
        count = InboxEntry.objects.filter(submitted_by=request.user).count()
        return {'message_count': count}
    return {'message_count': 0}


def health_summary(request):
    if request.user.is_authenticated and request.user.is_superuser:
        try:
            from .health import count_issues
            return {'health_issues_count': count_issues()}
        except Exception:
            return {'health_issues_count': 0}
    return {'health_issues_count': 0}


def app_settings(request):
    try:
        from django.conf import settings as django_settings
        settings = AppSettings.load()

        # Apply session timeout from app settings
        django_settings.SESSION_COOKIE_AGE = settings.session_timeout_minutes * 60

        result = {
            'app_timezone': settings.timezone,
            'app_timestamp_format': settings.timestamp_format,
            'otf_brand_name': settings.otf_brand_name or 'KineticLull Secure File Access',
            'otf_brand_bg_color': settings.otf_brand_bg_color or '#1a1d21',
            'otf_brand_text_color': settings.otf_brand_text_color or '#a0a4ab',
            'otf_brand_card_color': settings.otf_brand_card_color or '#1a1d21',
            'otf_brand_card_text_color': settings.otf_brand_card_text_color or '#a0a4ab',
            'otf_brand_image': settings.otf_brand_image.url if settings.otf_brand_image else '',
        }
        # Lightweight integrity check for superusers
        if request.user.is_authenticated and request.user.is_superuser and settings.db_checksum:
            from .views import compute_db_checksum
            if settings.db_checksum != compute_db_checksum():
                result['integrity_warning'] = True
        return result
    except Exception:
        return {'app_timezone': 'UTC', 'app_timestamp_format': 'Y-m-d H:i:s'}
