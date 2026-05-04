import os
import hashlib
import secrets

from django.db import models
from django.conf import settings
from .crypto import EncryptedCharField
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
            models.Model.save(entry, update_fields=['chain_hash'])

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
    timezone_configured = models.BooleanField(default=False, verbose_name='Timezone has been configured')
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

    # EDL Protection
    edl_delete_protection = models.BooleanField(default=True, verbose_name='Enable Active EDL Delete Protection')
    edl_delete_threshold = models.PositiveIntegerField(default=3, verbose_name='Min accesses to protect')
    edl_delete_window_minutes = models.PositiveIntegerField(default=15, verbose_name='Protection window (minutes)')

    # Auto-block
    autoblock_enabled = models.BooleanField(default=False, verbose_name='Enable Auto-Block')
    autoblock_threshold = models.PositiveIntegerField(default=50, verbose_name='Auto-Block Threshold (requests)')
    autoblock_window_seconds = models.PositiveIntegerField(default=60, verbose_name='Auto-Block Window (seconds)')
    autoblock_duration_minutes = models.PositiveIntegerField(default=0, verbose_name='Auto-Block Duration (minutes, 0=permanent)')

    # Failed-login block (separate rule from general auto-block)
    failed_login_block_enabled = models.BooleanField(default=True, verbose_name='Enable Failed-Login Block')
    failed_login_block_threshold = models.PositiveIntegerField(default=3, verbose_name='Failed-Login Block Threshold')
    failed_login_warning_threshold = models.PositiveIntegerField(default=2, verbose_name='Failed-Login Warning Threshold')
    failed_login_window_hours = models.PositiveIntegerField(default=24, verbose_name='Failed-Login Window (hours)')

    # Email (Resend)
    resend_api_key = EncryptedCharField(max_length=512, blank=True, default='', verbose_name='Resend API Key')
    resend_from_name = models.CharField(max_length=255, blank=True, default='', verbose_name='From Name')
    resend_from_email = models.EmailField(max_length=255, blank=True, default='', verbose_name='From Email Address')

    # File Sharing
    max_file_size_mb = models.PositiveIntegerField(default=250, verbose_name='Max file size (MB)')
    otf_brand_name = models.CharField(max_length=255, blank=True, default='KineticLull Secure File Access', verbose_name='File Share Brand Name')
    otf_brand_bg_color = models.CharField(max_length=7, blank=True, default='#1a1d21', verbose_name='Brand Background Color')
    otf_brand_text_color = models.CharField(max_length=7, blank=True, default='#a0a4ab', verbose_name='Brand Text Color')
    otf_brand_card_color = models.CharField(max_length=7, blank=True, default='#1a1d21', verbose_name='Card Background Color')
    otf_brand_card_text_color = models.CharField(max_length=7, blank=True, default='#a0a4ab', verbose_name='Card Text Color')
    otf_brand_image = models.FileField(upload_to='branding/', blank=True, verbose_name='Brand Logo')

    # Backups (Backblaze B2)
    b2_enabled = models.BooleanField(default=False, verbose_name='Enable B2 Offsite Backup')
    b2_application_key_id = models.CharField(max_length=64, blank=True, default='', verbose_name='B2 keyID')
    b2_application_key = EncryptedCharField(max_length=512, blank=True, default='', verbose_name='B2 applicationKey')
    b2_bucket_name = models.CharField(max_length=255, blank=True, default='', verbose_name='B2 Bucket Name')
    b2_last_upload_at = models.DateTimeField(null=True, blank=True, verbose_name='B2 Last Upload')
    b2_last_upload_status = models.CharField(max_length=16, blank=True, default='', verbose_name='B2 Last Upload Status')
    b2_last_upload_filename = models.CharField(max_length=255, blank=True, default='', verbose_name='B2 Last Uploaded File')
    b2_last_upload_error = models.TextField(blank=True, default='', verbose_name='B2 Last Upload Error')

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

    # Path patterns that indicate scanner / exploit probing — any single hit
    # blocks the source IP immediately, regardless of rate. These are paths a
    # legitimate user has zero reason to ever request. Substrings are matched
    # case-insensitively against the URL path. Add only signals you're confident
    # carry no false positives — operator complaints about over-blocking belong
    # higher in the priority queue than missing a scanner.
    SCANNER_PATH_PATTERNS = (
        '.env',
        '.git/',
        'wp-admin',
        'wp-login',
        'wp-content/plugins',
        'phpmyadmin',
        '.aws/credentials',
        '/etc/passwd',
        '/etc/shadow',
        'id_rsa',
        'server-status',
        'web.config',
        '/cgi-bin/',
        'xmlrpc.php',
        'sftp-config',
        'vendor/phpunit',
        'eval-stdin.php',
        '/owa/',
        '/ecp/',
        'autodiscover.xml',
    )

    @classmethod
    def _matched_scanner_pattern(cls, path):
        if not path:
            return None
        lower = path.lower()
        for pat in cls.SCANNER_PATH_PATTERNS:
            if pat in lower:
                return pat
        return None

    @classmethod
    def check_scanner_pattern_block(cls, ip_address, path):
        """Immediately block an IP that hits a known scanner/exploit path.

        Gated by the same `autoblock_enabled` master switch as the rate-based
        check. Returns True if a block was created, False otherwise.
        """
        if not ip_address:
            return False
        app_settings = AppSettings.load()
        if not app_settings.autoblock_enabled:
            return False
        if WhitelistedIP.is_whitelisted(ip_address):
            return False
        if cls.objects.filter(ip_address=ip_address).exists():
            return False

        pattern = cls._matched_scanner_pattern(path)
        if not pattern:
            return False

        from django.utils import timezone
        from datetime import timedelta
        expires = None
        if app_settings.autoblock_duration_minutes > 0:
            expires = timezone.now() + timedelta(minutes=app_settings.autoblock_duration_minutes)

        cls.objects.create(
            ip_address=ip_address,
            reason=f'Auto-blocked: scanner pattern "{pattern}" in {path[:120]}',
            auto_blocked=True,
            expires_at=expires,
        )
        cls.sync_to_nginx()
        return True

    @classmethod
    def check_autoblock(cls, ip_address):
        """Check if an IP should be auto-blocked based on threshold settings."""
        from django.utils import timezone
        from datetime import timedelta

        app_settings = AppSettings.load()
        if not app_settings.autoblock_enabled:
            return False

        # Never block whitelisted IPs
        if WhitelistedIP.is_whitelisted(ip_address):
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

    @classmethod
    def count_recent_failed_logins(cls, ip_address):
        """Count login_failed events from an IP since the later of: window start, or last successful login from that IP."""
        from django.utils import timezone
        from datetime import timedelta

        app_settings = AppSettings.load()
        cutoff = timezone.now() - timedelta(hours=app_settings.failed_login_window_hours)

        last_success = (
            ActivityLog.objects.filter(action='login', ip_address=ip_address)
            .order_by('-created_at')
            .values_list('created_at', flat=True)
            .first()
        )
        if last_success and last_success > cutoff:
            cutoff = last_success

        return ActivityLog.objects.filter(
            action='login_failed',
            ip_address=ip_address,
            created_at__gte=cutoff,
        ).count()

    @classmethod
    def check_failed_login_block(cls, ip_address):
        """Apply the failed-login block rule. Returns 'blocked', 'warning', or None."""
        app_settings = AppSettings.load()
        if not app_settings.failed_login_block_enabled:
            return None
        if WhitelistedIP.is_whitelisted(ip_address):
            return None
        if cls.objects.filter(ip_address=ip_address).exists():
            return None

        count = cls.count_recent_failed_logins(ip_address)

        if count >= app_settings.failed_login_block_threshold:
            cls.objects.create(
                ip_address=ip_address,
                reason=f'Auto-blocked: {count} failed logins in {app_settings.failed_login_window_hours}h',
                auto_blocked=True,
            )
            cls.sync_to_nginx()
            return 'blocked'

        if count >= app_settings.failed_login_warning_threshold:
            return 'warning'

        return None


class WhitelistedIP(models.Model):
    ip_address = models.CharField(max_length=50, unique=True, verbose_name='IP Address or Subnet')
    reason = models.CharField(max_length=255, blank=True)
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, verbose_name='Added By'
    )
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Whitelisted IP"
        verbose_name_plural = "Whitelisted IPs"
        ordering = ["-added_at"]

    def __str__(self):
        return self.ip_address

    @classmethod
    def is_whitelisted(cls, ip_address):
        """Check if an IP is whitelisted (exact match or within a subnet)."""
        import ipaddress as iplib
        try:
            addr = iplib.ip_address(ip_address)
        except ValueError:
            return False
        for entry in cls.objects.all():
            try:
                if '/' in entry.ip_address:
                    if addr in iplib.ip_network(entry.ip_address, strict=False):
                        return True
                else:
                    if addr == iplib.ip_address(entry.ip_address):
                        return True
            except ValueError:
                continue
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


class ShortenedURL(models.Model):
    original_url = models.URLField(max_length=2048, verbose_name='Original URL')
    short_code = models.CharField(max_length=255, unique=True, blank=True)
    notes = models.TextField(blank=True, default='', verbose_name='Notes')
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shortened_urls')
    hit_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Shortened URL"
        verbose_name_plural = "Shortened URLs"
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if not self.short_code:
            self.short_code = secrets.token_urlsafe(8) + ".kl"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.short_code} -> {self.original_url}"


class OneTimeFile(models.Model):
    EXPIRY_CHOICES = [
        (1, '1 hour'),
        (6, '6 hours'),
        (12, '12 hours'),
        (24, '1 day'),
        (72, '3 days'),
        (168, '7 days'),
    ]

    file = models.FileField(upload_to='otf/', verbose_name='File')
    original_filename = models.CharField(max_length=500, verbose_name='Original Filename')
    token = models.CharField(max_length=64, unique=True, blank=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='uploaded_files')
    recipient_email = models.EmailField(verbose_name='Recipient Email')
    otp = models.CharField(max_length=6, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    expiry_hours = models.PositiveIntegerField(default=24, choices=EXPIRY_CHOICES, verbose_name='Expires After')
    expires_at = models.DateTimeField(verbose_name='Expires At')
    downloaded = models.BooleanField(default=False)
    downloaded_at = models.DateTimeField(null=True, blank=True)
    burned = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "One-Time File"
        verbose_name_plural = "One-Time Files"
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(32) + ".kl"
        if not self.expires_at:
            from django.utils import timezone
            from datetime import timedelta
            self.expires_at = timezone.now() + timedelta(hours=self.expiry_hours)
        # Ensure upload directory exists
        from django.conf import settings as django_settings
        upload_dir = os.path.join(django_settings.MEDIA_ROOT, 'otf')
        os.makedirs(upload_dir, exist_ok=True)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.original_filename} ({self.token[:8]}...)"

    @property
    def is_expired(self):
        from django.utils import timezone
        return timezone.now() >= self.expires_at

    @property
    def is_available(self):
        return not self.downloaded and not self.burned and not self.is_expired

    def generate_otp(self):
        """Generate a 6-digit OTP valid for 5 minutes."""
        import random
        from django.utils import timezone
        self.otp = f'{random.randint(100000, 999999)}'
        self.otp_created_at = timezone.now()
        self.save(update_fields=['otp', 'otp_created_at'])
        return self.otp

    def verify_otp(self, code):
        """Verify the OTP. Returns True if valid and not expired."""
        from django.utils import timezone
        from datetime import timedelta
        if not self.otp or not self.otp_created_at:
            return False
        if timezone.now() > self.otp_created_at + timedelta(minutes=5):
            return False
        return self.otp == code.strip()

    def burn(self):
        """Mark as burned and delete the file from disk."""
        from django.utils import timezone
        self.burned = True
        if not self.downloaded_at and self.downloaded:
            self.downloaded_at = timezone.now()
        self.save()
        if self.file:
            try:
                self.file.delete(save=False)
            except Exception:
                pass


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