from django.db import models
from django.db.models import Q
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin

from .managers import CustomUserManager


class CustomUser(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(_("first name"), max_length=30, blank=True)
    last_name = models.CharField(_("last name"), max_length=150, blank=True)
    email = models.EmailField(_("email address"), unique=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return self.email
    
class APIKey(models.Model):
    """A bearer credential for the `/api/v1/` surface.

    Keys are stored as a SHA-256 digest, never in plaintext. These are
    `secrets.token_urlsafe(50)` values (~400 bits of entropy), so there is no
    dictionary to attack and no reason to pay a slow-hash cost on every
    authenticated request. A plain digest also keeps the lookup a single
    indexed query, which a salted bcrypt/argon2 hash could not.

    The plaintext is shown to the operator exactly once, at generation.
    `key_prefix` is retained so a key stays identifiable in the UI and in
    support conversations afterwards.
    """

    SCOPE_WILDCARD = '*'
    SCOPE_EDL_WRITE = 'edl:write'
    SCOPE_USERID_WRITE = 'userid:write'

    SCOPE_CHOICES = [
        (SCOPE_WILDCARD, 'All endpoints'),
        (SCOPE_EDL_WRITE, 'Submit and update EDLs'),
        (SCOPE_USERID_WRITE, 'Submit user-to-IP mappings'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='api_keys')
    # Retained so workers running pre-hash code keep authenticating across an
    # upgrade. Blanked by migration 0005 and never written again.
    key = models.CharField(max_length=255, blank=True, default='', db_default='')
    key_hash = models.CharField(
        max_length=64, blank=True, default='', db_default='', db_index=True,
        verbose_name='Key Hash',
    )
    key_prefix = models.CharField(
        max_length=12, blank=True, default='', db_default='',
        verbose_name='Key Prefix',
    )
    name = models.CharField(
        max_length=100, blank=True, default='', db_default='',
        verbose_name='Label',
        help_text='What uses this key, e.g. "GhostHunter" or "Chromebook User-ID".',
    )
    scopes = models.JSONField(
        default=list, blank=True,
        verbose_name='Scopes',
        help_text='Endpoint groups this key may call. "*" grants everything.',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True, verbose_name='Last Used')
    revoked_at = models.DateTimeField(null=True, blank=True, verbose_name='Revoked')

    class Meta:
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"
        ordering = ["-created_at"]
        permissions = [
            ('use_api_key', 'Can use an API key'),
        ]
        constraints = [
            # Two keys must never share a digest, but a row can exist briefly
            # with no key yet, so the constraint has to skip the empty case.
            models.UniqueConstraint(
                fields=['key_hash'],
                condition=~Q(key_hash=''),
                name='unique_nonempty_api_key_hash',
            ),
        ]

    @staticmethod
    def hash_key(raw_key: str) -> str:
        """Return the lookup digest for a raw key. Empty in, empty out."""
        import hashlib

        raw_key = (raw_key or '').strip()
        if not raw_key:
            return ''
        return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()

    @property
    def is_expired(self):
        if self.expires_at is None:
            return False
        return timezone.now() > self.expires_at

    @property
    def is_revoked(self):
        return self.revoked_at is not None

    @property
    def is_usable(self):
        return not self.is_expired and not self.is_revoked

    def has_scope(self, scope: str) -> bool:
        """True when this key may call an endpoint requiring `scope`.

        Keys carrying the wildcard satisfy everything. Keys with no scopes at
        all are treated as wildcard too: that is the state every key migrated
        from the pre-scope schema lands in, and silently locking those out
        would break deployed GhostHunter installs.
        """
        scopes = self.scopes or []
        if not scopes or self.SCOPE_WILDCARD in scopes:
            return True
        return scope in scopes

    @property
    def display_key(self):
        """Masked identifier safe to render in the UI."""
        return f"{self.key_prefix}..." if self.key_prefix else "(hidden)"

    def __str__(self):
        return f"{self.user.email} - {self.display_key}"
