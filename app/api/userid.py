"""User-to-IP mapping ingest for PAN-OS User-ID.

A managed browser extension posts the signed-in identity on a heartbeat. The
address is taken from the connection, never from the body, so a client can
only ever claim an identity for traffic it actually originates.

A background thread in `app.apps` batches what lands here and pushes it to the
firewall; nothing in this module talks to PAN-OS directly. That split is what
keeps a morning full of logins from turning into a morning full of firewall
requests.
"""

from django.core.exceptions import PermissionDenied
from ninja import Router

from users.models import APIKey

from . import services
from .auth import APIKeyAuth, SessionAuth
from .schemas import ErrorOut, UserIdCheckinIn, UserIdCheckinOut, UserIdConfigOut

router = Router(tags=["User-ID"])

userid_auth = APIKeyAuth(APIKey.SCOPE_USERID_WRITE)


@router.post(
    "/checkin",
    auth=userid_auth,
    url_name="userid_checkin",
    response={200: UserIdCheckinOut, 400: ErrorOut, 403: ErrorOut},
    summary="Report the signed-in user at this address",
)
def checkin(request, payload: UserIdCheckinIn):
    """Record a user-to-IP mapping and return the collector's current config.

    The config rides along on the response so a heartbeat is a single round
    trip and the extension cannot drift out of date with the server.
    """
    from app.models import AppSettings
    from app.views import get_client_ip, log_activity

    app_settings = AppSettings.load()
    body, status, context = services.record_user_id_checkin(
        payload.username,
        get_client_ip(request),
        app_settings,
        device_id=payload.device_id,
        agent_version=payload.agent_version,
        chrome_version=payload.chrome_version,
    )

    # Only an address changing hands is worth an audit entry. Logging every
    # heartbeat would write an ActivityLog row, a syslog forward, a retention
    # purge, and a checksum recompute per device per interval, and would bury
    # the hash-chained audit log under traffic that says nothing.
    if status == 200 and context.get('identity_changed'):
        mapping = context['mapping']
        previous = context.get('previous_username')
        detail = f'was {previous}' if previous else 'new mapping'
        log_activity(request, 'userid_mapping', f'{mapping.username} @ {mapping.ip_address}',
                     detail, user=request.auth)

    return status, body


@router.get(
    "/config",
    auth=userid_auth,
    url_name="userid_config",
    response=UserIdConfigOut,
    summary="Collector configuration",
)
def config(request):
    """Settings for a collector that has not checked in yet (cold start)."""
    from app.models import AppSettings

    return services.userid_config(AppSettings.load())


@router.post("/test-connection", auth=SessionAuth, url_name="panos_test_connection",
             summary="Probe the firewall without changing anything")
def test_connection(request):
    """Confirm host, key, and TLS settings from the settings page.

    Does not touch the push status fields: a connectivity probe should not
    make a healthy integration look like it just failed, nor a failing one
    look recovered.
    """
    from app import panos
    from app.models import AppSettings

    if not request.user.is_superuser:
        raise PermissionDenied

    ok, message = panos.test_connection(AppSettings.load())
    return {'status': 'ok' if ok else 'error', 'message': message}


@router.post("/push-now", auth=SessionAuth, url_name="panos_push_now",
             summary="Run a push pass immediately")
def push_now(request):
    """Run exactly the pass the scheduler runs, on demand.

    Shares the scheduler's code path rather than reimplementing it, so what
    the button does and what the thread does cannot diverge.
    """
    from app.apps import push_due_user_id_mappings
    from app.models import AppSettings
    from app.views import log_activity

    if not request.user.is_superuser:
        raise PermissionDenied

    app_settings = AppSettings.load()
    if not app_settings.panos_enabled:
        return {'status': 'error', 'message': 'PAN-OS User-ID push is disabled in settings.'}

    count, message = push_due_user_id_mappings(app_settings)
    log_activity(request, 'userid_push', f'{count} mappings', message)
    return {'status': 'ok', 'count': count, 'message': message}
