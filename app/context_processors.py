# context_processors.py
from .models import InboxEntry

def inbox_count(request):
    if request.user.is_authenticated:
        count = InboxEntry.objects.filter(submitted_by=request.user).count()
        return {'message_count': count}
    return {'message_count': 0}
