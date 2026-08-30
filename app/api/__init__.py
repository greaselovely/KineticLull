"""KineticLull public API, served by Django Ninja at `/api/v1/`.

Layout:
    decorators.py  view decorators (docs gating)
    auth.py        bearer-key and session authentication classes
    schemas.py     request/response models shared across routers
    services.py    business logic, called by both v1 routes and the
                   legacy compatibility shims in `app.views`
    edl.py         EDL ingest (GhostHunter, customer scripts)
    security.py    block / whitelist operations for the browser UI
    system.py      version probe, service restart
    userid.py      user-to-IP mapping ingest for PAN-OS User-ID

Legacy paths (`/api/submit_fqdn/`, `/api/update_edl/`, `/api/v0/boot_version/`)
stay mounted in `app/urls.py` as thin shims over `services.py`. They are
hardcoded in shipped GhostHunter builds and customer scripts, so their paths
and wire shapes are frozen.
"""

from django.http import JsonResponse
from ninja import NinjaAPI
from ninja.errors import AuthenticationError, HttpError, ValidationError

from .decorators import superuser_required

api = NinjaAPI(
    title="KineticLull API",
    version="1.0.0",
    description="EDL management, security controls, and telemetry ingest.",
    urls_namespace="api_v1",
    docs_decorator=superuser_required,
)

@api.exception_handler(AuthenticationError)
def on_auth_error(request, exc):
    """Match the error shape the pre-v1 endpoints have always returned.

    Ninja's default is `{"detail": ...}`. The legacy endpoints, and every
    other response on this API, use `{"error": ...}`. One shape means a client
    needs one branch to read a failure.
    """
    return JsonResponse({'error': 'Unauthorized'}, status=401)


@api.exception_handler(HttpError)
def on_http_error(request, exc):
    """Keep deliberately raised errors in the same `{"error": ...}` shape."""
    return JsonResponse({'error': str(exc)}, status=exc.status_code)


@api.exception_handler(ValidationError)
def on_validation_error(request, exc):
    """Flatten Pydantic's error list into the same single-string shape.

    The full list stays available under `detail` for anyone debugging against
    Swagger, but `error` is a readable sentence pointing at the first problem.
    """
    first = exc.errors[0] if exc.errors else {}
    location = '.'.join(str(part) for part in first.get('loc', [])[1:]) or 'request'
    message = first.get('msg', 'Invalid request')
    return JsonResponse(
        {'error': f'{location}: {message}', 'detail': exc.errors},
        status=422,
    )


# Imported here rather than at the top so the routers can import `api`-adjacent
# helpers without a cycle.
from .edl import router as edl_router  # noqa: E402
from .security import router as security_router  # noqa: E402
from .system import router as system_router  # noqa: E402
from .userid import router as userid_router  # noqa: E402

api.add_router("/edl/", edl_router)
api.add_router("/security/", security_router)
api.add_router("/system/", system_router)
api.add_router("/userid/", userid_router)
