"""Authentication for the `/api/v1/` surface.

Two callers, two classes:

* `APIKeyAuth` - machine clients (GhostHunter, customer scripts, the
  Chromebook User-ID extension) presenting a bearer key.
* `SessionAuth` - the browser UI's own fetch() calls, riding the existing
  Django session and CSRF token.

Scope enforcement lives here rather than in each operation so that adding an
endpoint cannot accidentally ship without an authorization check.
"""

from datetime import timedelta

from django.http import HttpRequest
from django.utils import timezone
from ninja.errors import HttpError
from ninja.security import HttpBearer
from ninja.security import django_auth

from users.models import APIKey

# How stale `last_used_at` is allowed to get before we spend a write on it.
# A key used by hundreds of Chromebooks on a heartbeat would otherwise add an
# UPDATE to every request, which SQLite does not need. One minute keeps the
# "is this integration alive?" signal useful without the write amplification.
LAST_USED_WRITE_INTERVAL = timedelta(seconds=60)


def resolve_api_key(raw_key: str):
    """Return the usable APIKey matching `raw_key`, or None.

    Rejects expired and revoked keys. Touches `last_used_at` at most once per
    `LAST_USED_WRITE_INTERVAL`.
    """
    key_hash = APIKey.hash_key(raw_key)
    if not key_hash:
        return None

    api_key = APIKey.objects.filter(key_hash=key_hash).select_related('user').first()
    if api_key is None or not api_key.is_usable:
        return None

    now = timezone.now()
    if api_key.last_used_at is None or now - api_key.last_used_at > LAST_USED_WRITE_INTERVAL:
        # Targeted UPDATE so a concurrent request cannot clobber other columns.
        APIKey.objects.filter(pk=api_key.pk).update(last_used_at=now)
        api_key.last_used_at = now

    return api_key


class APIKeyAuth(HttpBearer):
    """Bearer-key auth, optionally requiring one or more scopes.

    Accepts both `Authorization: Bearer <key>` and a bare `Authorization:
    <key>`. The bare form is not good practice, but the pre-v1 endpoint
    accepted it and there are keys deployed in the field that rely on it.
    Dropping it would break customers on upgrade for no security gain.
    """

    def __init__(self, *required_scopes: str):
        self.required_scopes = required_scopes
        super().__init__()

    def __call__(self, request: HttpRequest):
        auth_value = request.headers.get(self.header)
        if not auth_value:
            return None

        parts = auth_value.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == self.openapi_scheme:
            token = parts[1]
        elif len(parts) == 1:
            token = parts[0]
        else:
            return None

        return self.authenticate(request, token.strip())

    def authenticate(self, request: HttpRequest, token: str):
        api_key = resolve_api_key(token)
        if api_key is None:
            return None

        missing = [s for s in self.required_scopes if not api_key.has_scope(s)]
        if missing:
            self.log_scope_violation(request, api_key, missing)
            # 403, not 401: the key is genuine and unexpired, it simply is not
            # allowed here. Answering 401 would send a client off to re-fetch a
            # credential that was never the problem.
            raise HttpError(403, f'Key is not scoped for {", ".join(missing)}')

        # Downstream code wants the acting user; the key itself rides along
        # for operations that care which integration called.
        request.api_key = api_key
        return api_key.user

    def log_scope_violation(self, request, api_key, missing):
        """Record a key reaching outside its declared scopes.

        Deliberately audit-only for now. Auto-revoke on scope violation is a
        planned response tier, but wiring it here would let a single typo in
        an endpoint's scope declaration disable a customer's integration.
        """
        from app.views import log_activity

        try:
            log_activity(
                request,
                'api_scope_violation',
                api_key.display_key,
                f"required {', '.join(missing)}; key has {api_key.scopes or ['*']}",
                user=api_key.user,
            )
        except Exception:
            pass


#: Session + CSRF auth for the browser UI's own fetch() calls.
SessionAuth = django_auth
