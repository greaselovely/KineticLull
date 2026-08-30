"""View decorators shared by the API layer.

Kept in their own module so `app.api.__init__` can import them without
dragging in the routers (which in turn import models) at module scope.
"""

from django.core.exceptions import PermissionDenied


def superuser_required(view):
    """Restrict a plain Django view to authenticated superusers.

    Used to gate the OpenAPI schema and Swagger UI. On an internet-facing
    install those pages are a free map of every endpoint, parameter, and
    schema we expose, so they are not public. Anonymous or non-superuser
    callers get a 403 rather than a login redirect, because these are
    developer surfaces and a redirect just leaks that the path exists.
    """

    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_superuser:
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return wrapper
