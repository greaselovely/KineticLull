# context_processors.py
import hashlib
from .models import InboxEntry, AppSettings, ActivityLog, ExtDynLists


def inbox_count(request):
    if request.user.is_authenticated:
        count = InboxEntry.objects.filter(submitted_by=request.user).count()
        return {'message_count': count}
    return {'message_count': 0}


def app_settings(request):
    try:
        settings = AppSettings.load()
        result = {
            'app_timezone': settings.timezone,
            'app_timestamp_format': settings.timestamp_format,
        }
        # Lightweight integrity check for superusers
        if request.user.is_authenticated and request.user.is_superuser and settings.db_checksum:
            from .views import compute_db_checksum
            if settings.db_checksum != compute_db_checksum():
                result['integrity_warning'] = True
        return result
    except Exception:
        return {'app_timezone': 'UTC', 'app_timestamp_format': 'Y-m-d H:i:s'}
