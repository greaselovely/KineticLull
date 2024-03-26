# context_processors.py
from .models import InboxEntry

def inbox_count(request):
    if request.user.is_authenticated:
        user_email = request.user.email
        count = InboxEntry.objects.filter(user_email=user_email).count()
        return {'message_count': count}
    return {'message_count': 0}
