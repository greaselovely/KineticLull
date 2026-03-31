import os
import hashlib
import secrets

from django.db import models
from django.conf import settings
from django.contrib.auth.models import Group

class ExtDynLists(models.Model):
    friendly_name = models.CharField(max_length=255, verbose_name='EDL Name')
    auto_url = models.CharField(max_length=255, unique=True, blank=True)
    ip_fqdn = models.TextField(verbose_name='IP/FQDN')
    acl = models.TextField(verbose_name='ACL')
    policy_reference = models.TextField(verbose_name='Notes')
    groups = models.ManyToManyField(Group, blank=True, verbose_name='Groups')
    created_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Ext Dyn List"
        verbose_name_plural = "Ext Dyn Lists"
        ordering = ["created_date", "friendly_name"]

    def save(self, *args, **kwargs):
        if not self.auto_url:
            self.auto_url = secrets.token_urlsafe(16) + ".kl"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.id}: {self.friendly_name} ({self.auto_url})" 

    # def update(self):
    #     if self.use_script and self.use_script.is_approved:
    #         # Execute the script as it has been approved
    #         exec(self.use_script.content)  # Be cautious with `exec`, as it poses a security risk
    #     else:
    #         print(f"Script for {self.friendly_name} is not approved or found.")


class Favorite(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='favorites')
    edl = models.ForeignKey(ExtDynLists, on_delete=models.CASCADE, related_name='favorited_by')

    class Meta:
        unique_together = ('user', 'edl')
        verbose_name = "Favorite"
        verbose_name_plural = "Favorites"

    def __str__(self):
        return f"{self.user.email} -> {self.edl.friendly_name}"


class ActivityLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=50)
    target = models.CharField(max_length=255, blank=True)
    detail = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    chain_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        verbose_name = "Activity Log"
        verbose_name_plural = "Activity Logs"
        ordering = ["-created_at"]

    def _compute_hash(self, prev_hash=''):
        data = f"{prev_hash}|{self.user_id}|{self.action}|{self.target}|{self.detail}|{self.ip_address}"
        return hashlib.sha256(data.encode()).hexdigest()

    def save(self, *args, **kwargs):
        if not self.chain_hash:
            last = ActivityLog.objects.order_by('-id').first()
            prev_hash = last.chain_hash if last else ''
            self.chain_hash = self._compute_hash(prev_hash)
        super().save(*args, **kwargs)

    @classmethod
    def verify_chain(cls):
        """Verify the integrity of the log chain. Returns (valid, first_broken_id)."""
        prev_hash = ''
        for entry in cls.objects.order_by('id'):
            expected = entry._compute_hash(prev_hash)
            if entry.chain_hash != expected:
                return False, entry.id
            prev_hash = entry.chain_hash
        return True, None

    @classmethod
    def rebase_chain(cls):
        """Recalculate all chain hashes from scratch. Use after legitimate deletions."""
        prev_hash = ''
        for entry in cls.objects.order_by('id'):
            entry.chain_hash = entry._compute_hash(prev_hash)
            prev_hash = entry.chain_hash
            super(ActivityLog, entry).save(update_fields=['chain_hash'])

    def __str__(self):
        return f"{self.created_at} {self.user} {self.action} {self.target}"


class AppSettings(models.Model):
    DEPLOYMENT_CHOICES = [
        ('gunicorn_ssl', 'Gunicorn (direct SSL)'),
        ('nginx_gunicorn', 'Nginx + Gunicorn'),
    ]

    TIMESTAMP_CHOICES = [
        ('Y-m-d H:i:s', '2026-03-17 14:30:00'),
        ('m/d/Y H:i:s', '03/17/2026 14:30:00'),
        ('d/m/Y H:i:s', '17/03/2026 14:30:00'),
        ('M d, Y H:i:s', 'Mar 17, 2026 14:30:00'),
        ('M d, Y g:i:s A', 'Mar 17, 2026 2:30:00 PM'),
        ('Y-m-d g:i:s A', '2026-03-17 2:30:00 PM'),
        ('m/d/Y g:i:s A', '03/17/2026 2:30:00 PM'),
    ]
    # Display
    timezone = models.CharField(max_length=50, default='UTC', verbose_name='Display Timezone')
    timestamp_format = models.CharField(max_length=50, default='Y-m-d H:i:s', choices=TIMESTAMP_CHOICES, verbose_name='Timestamp Format')
    default_edl_per_page = models.PositiveIntegerField(default=10, verbose_name='Default EDLs per page')
    default_log_per_page = models.PositiveIntegerField(default=25, verbose_name='Default logs per page')
    edl_preview_entries = models.PositiveIntegerField(default=3, verbose_name='EDL preview entries on index')

    # API Limits
    max_fqdns_per_submission = models.PositiveIntegerField(default=50, verbose_name='Max FQDNs per API submission')
    max_fqdns_per_update = models.PositiveIntegerField(default=50, verbose_name='Max FQDNs per API update')

    # Data Limits
    max_edls_per_group = models.PositiveIntegerField(default=25, verbose_name='Max EDLs per group')
    max_entries_per_edl = models.PositiveIntegerField(default=5000, verbose_name='Max entries per EDL')
    max_inbox_per_user = models.PositiveIntegerField(default=25, verbose_name='Max inbox entries per user')

    # Retention
    log_retention_days = models.PositiveIntegerField(default=90, verbose_name='Log retention (days)')

    # Security
    session_timeout_minutes = models.PositiveIntegerField(default=30, verbose_name='Session inactivity timeout (minutes)')
    api_key_expiration_days = models.PositiveIntegerField(default=90, verbose_name='API key expiration (days)')

    # Syslog
    SYSLOG_PROTOCOL_CHOICES = [
        ('udp', 'UDP'),
        ('tcp', 'TCP'),
    ]
    syslog_enabled = models.BooleanField(default=False, verbose_name='Enable Syslog Forwarding')
    syslog_host = models.CharField(max_length=255, blank=True, default='', verbose_name='Syslog Host')
    syslog_port = models.PositiveIntegerField(default=514, verbose_name='Syslog Port')
    syslog_protocol = models.CharField(max_length=3, default='udp', choices=SYSLOG_PROTOCOL_CHOICES, verbose_name='Syslog Protocol')

    # Auto-block
    autoblock_enabled = models.BooleanField(default=False, verbose_name='Enable Auto-Block')
    autoblock_threshold = models.PositiveIntegerField(default=50, verbose_name='Auto-Block Threshold (requests)')
    autoblock_window_seconds = models.PositiveIntegerField(default=60, verbose_name='Auto-Block Window (seconds)')
    autoblock_duration_minutes = models.PositiveIntegerField(default=0, verbose_name='Auto-Block Duration (minutes, 0=permanent)')

    # Deployment
    deployment_mode = models.CharField(
        max_length=20, default='gunicorn_ssl',
        choices=DEPLOYMENT_CHOICES, verbose_name='Deployment Mode'
    )

    # Internal
    db_checksum = models.CharField(max_length=64, blank=True, verbose_name='DB Integrity Checksum')

    class Meta:
        verbose_name = "App Settings"
        verbose_name_plural = "App Settings"

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def __str__(self):
        return "App Settings"


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255, blank=True)
    blocked_at = models.DateTimeField(auto_now_add=True)
    blocked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, verbose_name='Blocked By'
    )
    auto_blocked = models.BooleanField(default=False)
    expires_at = models.DateTimeField(null=True, blank=True, verbose_name='Expires At')

    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ["-blocked_at"]

    def __str__(self):
        return f"{self.ip_address} ({'auto' if self.auto_blocked else 'manual'})"

    @property
    def is_expired(self):
        if self.expires_at is None:
            return False
        from django.utils import timezone
        return timezone.now() >= self.expires_at

    @classmethod
    def sync_to_nginx(cls):
        """Write the blocklist file and reload Nginx."""
        import subprocess
        from django.utils import timezone

        # Remove expired entries
        cls.objects.filter(expires_at__isnull=False, expires_at__lte=timezone.now()).delete()

        blocked = cls.objects.values_list('ip_address', flat=True)
        blocklist_path = os.path.join(settings.BASE_DIR, 'deploy', 'blocklist.conf')
        os.makedirs(os.path.dirname(blocklist_path), exist_ok=True)

        with open(blocklist_path, 'w') as f:
            for ip in blocked:
                f.write(f'deny {ip};\n')

        # Reload Nginx to pick up the new blocklist
        try:
            subprocess.run(
                ['sudo', 'nginx', '-s', 'reload'],
                capture_output=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # Nginx not installed or not running (dev environment)

    @classmethod
    def check_autoblock(cls, ip_address):
        """Check if an IP should be auto-blocked based on threshold settings."""
        from django.utils import timezone
        from datetime import timedelta

        app_settings = AppSettings.load()
        if not app_settings.autoblock_enabled:
            return False

        # Don't re-block if already blocked
        if cls.objects.filter(ip_address=ip_address).exists():
            return False

        window_start = timezone.now() - timedelta(seconds=app_settings.autoblock_window_seconds)
        hit_count = ActivityLog.objects.filter(
            ip_address=ip_address,
            action__in=['not_found', 'edl_not_found', 'edl_access'],
            created_at__gte=window_start,
        ).count()

        if hit_count >= app_settings.autoblock_threshold:
            expires = None
            if app_settings.autoblock_duration_minutes > 0:
                expires = timezone.now() + timedelta(minutes=app_settings.autoblock_duration_minutes)

            cls.objects.create(
                ip_address=ip_address,
                reason=f'Auto-blocked: {hit_count} hits in {app_settings.autoblock_window_seconds}s',
                auto_blocked=True,
                expires_at=expires,
            )
            cls.sync_to_nginx()
            return True
        return False


class NginxRejection(models.Model):
    """Stores parsed Nginx 403 rejections from blocked IPs."""
    ip_address = models.GenericIPAddressField(db_index=True)
    path = models.CharField(max_length=500)
    timestamp = models.DateTimeField(db_index=True)

    class Meta:
        verbose_name = "Nginx Rejection"
        verbose_name_plural = "Nginx Rejections"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.timestamp} {self.ip_address} {self.path}"

    @classmethod
    def purge_old(cls, days=30):
        from django.utils import timezone
        from datetime import timedelta
        cls.objects.filter(timestamp__lt=timezone.now() - timedelta(days=days)).delete()


class InboxEntry(models.Model):
    submitted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, verbose_name='Submitted By', null=True)
    fqdn_list = models.TextField(verbose_name='IP/FQDN')
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "API Submission"
        verbose_name_plural = "API Submissions"

# class Script(models.Model):
#     name = models.CharField(max_length=255, verbose_name='Script Name')
#     content = models.TextField(verbose_name='Script Content')
#     creator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='created_scripts', verbose_name='Script Creator', null=True)
#     is_approved = models.BooleanField(default=False, verbose_name='Approved for Execution')

#     class Meta:
#         verbose_name = "Script"
#         verbose_name_plural = "Scripts"

#     def __str__(self):
#         return self.name