"""EDL ingest endpoints.

These back GhostHunter and customer automation. The pre-v1 paths
(`/api/submit_fqdn/`, `/api/update_edl/`) remain mounted in `app/urls.py` as
shims over the same `services` functions, because they are hardcoded in
shipped extension builds and in scripts we do not control.
"""

from ninja import Router

from users.models import APIKey

from . import services
from .auth import APIKeyAuth
from .schemas import ErrorOut, MessageOut, SubmitFQDNIn, UpdateEDLIn

router = Router(tags=["EDL"])

edl_auth = APIKeyAuth(APIKey.SCOPE_EDL_WRITE)


@router.post(
    "/submit",
    auth=edl_auth,
    url_name="submit_fqdn",
    response={201: MessageOut, 400: ErrorOut},
    summary="Queue FQDNs for review",
)
def submit_fqdn(request, payload: SubmitFQDNIn):
    """Drop a list of domains into the Inbox for an operator to triage."""
    from app.views import log_activity

    body, status, context = services.submit_fqdns(request.auth, payload.fqdn_list)
    if status == 201:
        log_activity(request, 'api_submit', f'{context["count"]} FQDNs', user=request.auth)
    return status, body


@router.post(
    "/update",
    auth=edl_auth,
    url_name="update_edl",
    response={200: MessageOut, 400: ErrorOut, 403: ErrorOut, 404: ErrorOut},
    summary="Append to or overwrite an EDL",
)
def update_edl(request, payload: UpdateEDLIn):
    """Add domains to an existing EDL, or replace its contents outright."""
    from app.views import log_activity

    body, status, context = services.update_edl(
        request.auth, payload.auto_url, payload.fqdn_list, payload.command
    )
    if status == 200:
        log_activity(
            request,
            f'api_{context["command"]}',
            context['friendly_name'],
            f'{context["count"]} FQDNs',
        )
    return status, body
