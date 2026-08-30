"""System-level endpoints: version probing and service restart."""

from django.core.exceptions import PermissionDenied
from ninja import Router

from .auth import SessionAuth
from .schemas import BootVersionOut

router = Router(tags=["System"])


@router.get("/boot_version", auth=None, url_name="boot_version",
            response=BootVersionOut, summary="Version this worker is running")
def boot_version(request):
    """Compare the code a worker booted with against what is on disk.

    Unauthenticated on purpose: the upgrade page polls this to know when
    workers have actually picked up new code, and during that window the
    session may not survive. It discloses only a version string.
    """
    from app import health as _health
    from app.views import get_current_version

    return {
        'boot_version': _health.BOOT_VERSION or 'unknown',
        'disk_version': get_current_version(),
    }


@router.post("/restart-services", auth=SessionAuth, url_name="restart_services",
             summary="Restart KineticLull and Nginx")
def restart_services(request):
    """Collect static, patch nginx if needed, then restart both services.

    Delegates to the original view. This orchestrates privileged subprocesses
    and a restart that kills the worker running it; reimplementing it to gain
    a response schema would be all risk and no benefit.
    """
    from app.views import restart_services_view

    if not request.user.is_superuser:
        raise PermissionDenied
    return restart_services_view(request)
