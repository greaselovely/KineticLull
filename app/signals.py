from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver


@receiver(user_logged_in)
def handle_user_logged_in(sender, request, user, **kwargs):
    from .views import log_activity
    from .models import BlockedIP
    log_activity(request, 'login', target=user.email, user=user)


@receiver(user_logged_out)
def handle_user_logged_out(sender, request, user, **kwargs):
    from .views import log_activity
    if user is None:
        return
    log_activity(request, 'logout', target=user.email, user=user)


@receiver(user_login_failed)
def handle_user_login_failed(sender, credentials, request=None, **kwargs):
    from .views import log_activity, get_client_ip
    from .models import BlockedIP
    if request is None:
        return
    attempted = credentials.get('username') or credentials.get('email') or ''
    log_activity(request, 'login_failed', target=attempted, detail='Invalid credentials')
    ip = get_client_ip(request)
    if ip:
        BlockedIP.check_autoblock(ip)
