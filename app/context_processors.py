# context_processors.py
from .models import InboxEntry, AppSettings


def inbox_count(request):
    if request.user.is_authenticated:
        count = InboxEntry.objects.filter(submitted_by=request.user).count()
        return {'message_count': count}
    return {'message_count': 0}


def app_settings(request):
    try:
        settings = AppSettings.load()
        return {
            'app_timezone': settings.timezone,
            'app_timestamp_format': settings.timestamp_format,
        }
    except Exception:
        return {'app_timezone': 'UTC', 'app_timestamp_format': 'Y-m-d H:i:s'}
