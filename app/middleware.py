from django.shortcuts import redirect
from django.urls import reverse

from .models import AppSettings


class TimezoneCheckMiddleware:
    """Redirect superusers to settings page on login if timezone hasn't been configured."""

    EXEMPT_PATHS = ('/login/', '/logout/', '/settings/', '/static/', '/favicon.ico')

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (
            request.user.is_authenticated
            and request.user.is_superuser
            and not request.session.get('tz_check_done')
            and not any(request.path.startswith(p) for p in self.EXEMPT_PATHS)
        ):
            app_settings = AppSettings.load()
            if not app_settings.timezone_configured:
                request.session['tz_check_done'] = True
                return redirect(reverse('app:app_settings') + '?tz_setup=1')
            else:
                request.session['tz_check_done'] = True

        return self.get_response(request)
