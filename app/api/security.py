"""Block and whitelist operations for the browser UI.

Session-authenticated and superuser-only. These take form-encoded bodies
rather than JSON because that is what the existing `fetch()` calls in the
templates send, and there is no reason to churn working front-end code to
satisfy a convention.
"""

from django.core.exceptions import PermissionDenied
from ninja import Form, Router

from . import services
from .auth import SessionAuth
from .schemas import ErrorOut

router = Router(tags=["Security"], auth=SessionAuth)


def _require_superuser(request):
    """These endpoints administer the firewall in front of the whole install.

    Checked per operation rather than relying on the router's auth alone, so
    that adding a route here cannot accidentally expose it to any logged-in
    user.
    """
    if not request.user.is_superuser:
        raise PermissionDenied


@router.post("/block-ip", url_name="block_ip", response={200: dict, 400: ErrorOut},
             summary="Block an IP address")
def block_ip(request, ip_address: Form[str], reason: Form[str] = 'Manually blocked'):
    from app.views import log_activity

    _require_superuser(request)
    payload, status, context = services.block_ip(request.user, ip_address, reason)
    if status == 200 and context.get('created'):
        log_activity(request, 'ip_blocked', ip_address.strip(), context['reason'])
    return status, payload


@router.post("/unblock-ip", url_name="unblock_ip", response={200: dict, 400: ErrorOut},
             summary="Unblock an IP address")
def unblock_ip(request, ip_address: Form[str]):
    from app.views import log_activity

    _require_superuser(request)
    payload, status, context = services.unblock_ip(ip_address)
    if status == 200 and context.get('deleted'):
        log_activity(request, 'ip_unblocked', ip_address.strip())
    return status, payload


@router.post("/whitelist-ip", url_name="whitelist_ip", response={200: dict, 400: ErrorOut},
             summary="Whitelist an IP or subnet")
def whitelist_ip(request, ip_address: Form[str], reason: Form[str] = ''):
    from app.views import log_activity

    _require_superuser(request)
    payload, status, context = services.whitelist_ip(request.user, ip_address, reason)
    if status == 200 and context.get('created'):
        log_activity(request, 'whitelist_ip', ip_address.strip(), context['reason'])
    return status, payload


@router.post("/remove-whitelist-ip", url_name="remove_whitelist_ip",
             response={200: dict, 404: ErrorOut}, summary="Remove a whitelist entry")
def remove_whitelist_ip(request, ip_address: Form[str]):
    from app.views import log_activity

    _require_superuser(request)
    payload, status, _ = services.remove_whitelist_ip(ip_address)
    if status == 200:
        log_activity(request, 'remove_whitelist', ip_address.strip())
    return status, payload


@router.get("/blocked-ip-timeline", url_name="blocked_ip_timeline",
            summary="Rejection timeline for a blocked IP")
def blocked_ip_timeline(request):
    """Chart data for one blocked IP over a 24h / 7d / 30d window.

    Delegates to the original implementation rather than restating ~80 lines
    of timezone-aware bucketing and CIDR expansion. There is nothing to gain
    from a schema here: the response is chart-shaped data read by one
    template, and re-deriving it would only add a place for the two to
    disagree.
    """
    from app.views import blocked_ip_timeline_view

    _require_superuser(request)
    return blocked_ip_timeline_view(request)
