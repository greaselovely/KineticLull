import os
import hashlib
import secrets

from django.db import models
from django.conf import settings
from .crypto import EncryptedCharField, EncryptedTextField
from django.contrib.auth.models import Group


DEFAULT_ROBOTS_TXT = """\
# robots.txt for KineticLull
# An EDL (External Dynamic List) manager for network security teams who
# got tired of editing CSVs by hand and ssh'ing to the firewall at 2am
# to push a /32 block.
#
# Built by zeroonesix.co. Yes, that is a real TLD. No, .co is not a typo.
#
# ---------------------------------------------------------------------
# Dear crawler,
#
# This is a private appliance. There is nothing here for you to index.
# You have wandered into a server whose entire purpose in life is
# blocking other servers. Read the room.
#
# ---------------------------------------------------------------------
# To the human reading this in `view-source:` or `curl -s`:
#
# Welcome. The house rules are short:
#
#   - It is always DNS.
#   - rm -rf / is not a backup strategy.
#   - The S in IoT stands for Security.
#   - "It works on my machine" is not a deployment plan.
#   - Firewall rule order matters. yes, that one too.
#   - /dev/null is the most reliable database in production.
#   - tabs. it was always tabs.
#   - There are 10 kinds of people: those who understand binary,
#     those who don't, and those who weren't expecting base 3.
#
# ---------------------------------------------------------------------
# To the mass scanners, bored botnets, and that one curl loop someone
# forgot to systemctl stop in 2019:
#
#   - The stack you are guessing at is wrong.
#   - Your favorites list is on file. Try harder, or try elsewhere.
#   - The teapot is brewing. HTTP 418.
#
# ---------------------------------------------------------------------
# NDg2NTc5MmMyMDQ5MjA3MzY1NjUyMDc5NmY3NTJj
# MjA2MTZlNjQyMDc5NmY3NTIwNmU2Zjc3MjA3MzY1
# CjY1MjA2ZDY1MmMyMDczNmYyMDY0NzI2ZjcwMjA2
# MTIwNmU2Zjc0NjUyMDc3NmY3NTZjNjQyMDc5NjEz
# ZgoyMDIwMmQzZDIwNzM2ODYxNzk2ZTY1NDA3YTY1
# NzI2ZjZmNmU2NTczNjk3ODJlNjM2ZjIwM2QyZDIw
# MjAK
#
# no auth required,
# don't sell the contents, 
# and wear your pants backwards
# ¯\\_(ツ)_/¯
# ---------------------------------------------------------------------

User-agent: *
Disallow: /
"""

class ExtDynLists(models.Model):
    SYSTEM_BLOCKLIST_NAME = "System Blocklist - Auto-Blocked IPs"

    friendly_name = models.CharField(max_length=255, verbose_name='EDL Name')
    auto_url = models.CharField(max_length=255, unique=True, blank=True)
    ip_fqdn = models.TextField(verbose_name='IP/FQDN')
    acl = models.TextField(verbose_name='ACL')
    policy_reference = models.TextField(verbose_name='Notes')
    groups = models.ManyToManyField(Group, blank=True, verbose_name='Groups')
    created_date = models.DateTimeField(auto_now_add=True)
    is_system = models.BooleanField(default=False, editable=False)

    class Meta:
        verbose_name = "Ext Dyn List"
        verbose_name_plural = "Ext Dyn Lists"
        ordering = ["-is_system", "created_date", "friendly_name"]
        constraints = [
            # Partial unique index: at most one row with is_system=True.
            # Closes the multi-worker race where every gunicorn worker calls
            # sync_system_blocklist() in apps.ready() — without this, concurrent
            # get_or_create() can produce duplicate system EDL rows.
            models.UniqueConstraint(
                fields=['is_system'],
                condition=models.Q(is_system=True),
                name='unique_system_edl',
            ),
        ]

    def save(self, *args, **kwargs):
        if not self.auto_url:
            self.auto_url = secrets.token_urlsafe(16) + ".kl"
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if self.is_system:
            raise PermissionError("System EDL cannot be deleted.")
        return super().delete(*args, **kwargs)

    def __str__(self):
        return f"{self.id}: {self.friendly_name} ({self.auto_url})"

    @classmethod
    def sync_system_blocklist(cls):
        """Mirror every BlockedIP row into the pinned system EDL.

        Called from BlockedIP.sync_to_nginx, so every add/remove/expire path
        already in the codebase keeps the EDL in lockstep with the blocklist.
        Creates the singleton on first call. ip_fqdn is fully overwritten;
        operators can't edit it (the views and model.delete enforce this).
        """
        edl, created = cls.objects.get_or_create(
            is_system=True,
            defaults={
                'friendly_name': cls.SYSTEM_BLOCKLIST_NAME,
                'acl': '*',
                'policy_reference': (
                    'Auto-managed by KineticLull. Mirrors every IP in the '
                    'system blocklist (manual + scanner-pattern + failed-login '
                    'auto-blocks). Read-only, IPs are added and removed by '
                    'the app as the blocklist changes.'
                ),
                'ip_fqdn': '',
            },
        )
        ips = list(BlockedIP.objects.order_by('ip_address').values_list('ip_address', flat=True))
        new_body = "\r\n".join(ips)
        if edl.ip_fqdn != new_body:
            edl.ip_fqdn = new_body
            edl.save(update_fields=['ip_fqdn'])
        if created:
            # Creating a new EDL row bumps the count and max-id that
            # compute_db_checksum() hashes; re-baseline so the integrity
            # check doesn't fire on the first boot after this feature lands.
            try:
                from app.views import update_db_checksum
                update_db_checksum()
            except Exception:
                pass
        return edl

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
    user_agent = models.CharField(max_length=512, blank=True, default='', db_default='')
    referer = models.CharField(max_length=512, blank=True, default='', db_default='')
    created_at = models.DateTimeField(auto_now_add=True)
    chain_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        verbose_name = "Activity Log"
        verbose_name_plural = "Activity Logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=['ip_address', 'created_at']),
        ]

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
        """Verify the integrity of the log chain. Returns (valid, first_broken_id).

        Streams via iterator() so the integrity page doesn't load every row
        into memory on customer installs with 100k+ entries.
        """
        prev_hash = ''
        for entry in cls.objects.order_by('id').iterator(chunk_size=1000):
            expected = entry._compute_hash(prev_hash)
            if entry.chain_hash != expected:
                return False, entry.id
            prev_hash = entry.chain_hash
        return True, None

    @classmethod
    def rebase_chain(cls):
        """Recalculate all chain hashes from scratch. Use after legitimate deletions.

        Uses bulk_update inside a single transaction so that a customer with
        100k+ log entries doesn't time out the gunicorn worker (default 30s).
        """
        from django.db import transaction
        BATCH_SIZE = 1000
        prev_hash = ''
        batch = []
        with transaction.atomic():
            for entry in cls.objects.order_by('id').iterator(chunk_size=BATCH_SIZE):
                entry.chain_hash = entry._compute_hash(prev_hash)
                prev_hash = entry.chain_hash
                batch.append(entry)
                if len(batch) >= BATCH_SIZE:
                    cls.objects.bulk_update(batch, ['chain_hash'])
                    batch = []
            if batch:
                cls.objects.bulk_update(batch, ['chain_hash'])

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
    # Cumulative-window check — catches paced scanners that evade the burst window
    autoblock_long_threshold = models.PositiveIntegerField(default=30, verbose_name='Slow-Probe Threshold (cumulative hits)')
    autoblock_long_window_hours = models.PositiveIntegerField(default=24, verbose_name='Slow-Probe Window (hours)')
    # Operator-added scanner path patterns (one per line). Appended to the
    # built-in BlockedIP.SCANNER_PATH_PATTERNS tuple at match time.
    autoblock_custom_patterns = models.TextField(blank=True, default='', verbose_name='Custom Scanner Patterns')
    # Subnet aggregation: when N or more /32s from the same /24 are
    # auto-blocked, collapse them into a single /24 entry. IPv4 only.
    autoblock_subnet_aggregation_enabled = models.BooleanField(default=False, verbose_name='Enable /24 Aggregation')
    autoblock_subnet_threshold = models.PositiveIntegerField(default=5, verbose_name='Aggregation Threshold (auto-blocked /32 in same /24)')

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

    # Backups
    backup_time = models.TimeField(default='02:00', verbose_name='Daily backup time (in display timezone)')

    # Backups (Backblaze B2)
    b2_enabled = models.BooleanField(default=False, verbose_name='Enable B2 Offsite Backup')
    b2_application_key_id = models.CharField(max_length=64, blank=True, default='', verbose_name='B2 keyID')
    b2_application_key = EncryptedCharField(max_length=512, blank=True, default='', verbose_name='B2 applicationKey')
    b2_bucket_name = models.CharField(max_length=255, blank=True, default='', verbose_name='B2 Bucket Name')
    b2_last_upload_at = models.DateTimeField(null=True, blank=True, verbose_name='B2 Last Upload')
    b2_last_upload_status = models.CharField(max_length=16, blank=True, default='', verbose_name='B2 Last Upload Status')
    b2_last_upload_filename = models.CharField(max_length=255, blank=True, default='', verbose_name='B2 Last Uploaded File')
    b2_last_upload_error = models.TextField(blank=True, default='', verbose_name='B2 Last Upload Error')

    # robots.txt content served at /robots.txt — operator-editable.
    # Default lives in DEFAULT_ROBOTS_TXT and is seeded by AppSettings.load()
    # on first create. Keeping the field default empty means edits to
    # DEFAULT_ROBOTS_TXT do not generate stale-default migrations.
    robots_txt = models.TextField(default='', blank=True, verbose_name='robots.txt body')

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
        obj, _ = cls.objects.get_or_create(
            pk=1, defaults={'robots_txt': DEFAULT_ROBOTS_TXT},
        )
        return obj

    def get_custom_scanner_patterns(self):
        """Operator-added scanner patterns, normalized for matching.

        Lines shorter than 3 chars are dropped (would false-positive on
        common path fragments). Comments (#-prefixed), blank lines,
        duplicates, and entries that already exist in the built-in tuple
        are skipped. Caps at 200 entries.
        """
        if not self.autoblock_custom_patterns:
            return ()
        builtin = {p.lower() for p in BlockedIP.SCANNER_PATH_PATTERNS}
        seen = set()
        out = []
        for raw in self.autoblock_custom_patterns.splitlines():
            pat = raw.strip().lower()
            if not pat or pat.startswith('#') or len(pat) < 3:
                continue
            if pat in builtin or pat in seen:
                continue
            seen.add(pat)
            out.append(pat)
            if len(out) >= 200:
                break
        return tuple(out)

    def __str__(self):
        return "App Settings"


def is_globally_blockable(ip_address):
    """True only for globally-routable addresses that are safe to auto-block.

    SECURITY / SAFETY: loopback (127.0.0.0/8, ::1), private (RFC1918),
    link-local, multicast, reserved and unspecified addresses are rejected.
    Auto-blocking them is never useful and is actively dangerous:

      * Attackers forge these (commonly 127.0.0.1) in spoofable client-IP
        headers to make us block a bogus address instead of their real one.
        Even with correct IP detection, we refuse them as defence-in-depth so
        a single detection slip can never poison the blocklist.
      * The blocklist is mirrored into a firewall drop-EDL. A loopback or
        RFC1918 entry there can match legitimate internal / health-check
        traffic and cause an outage.

    Manual operator blocks bypass this helper; only the automated paths call
    it. IPv4 and IPv6 both handled via ipaddress.is_global.
    """
    import ipaddress as iplib
    try:
        addr = iplib.ip_address(ip_address)
    except ValueError:
        return False
    return addr.is_global


class BlockedIP(models.Model):
    # CharField (not GenericIPAddressField) so we can store both single
    # addresses and CIDR blocks (e.g. "10.0.0.0/24") produced by subnet
    # aggregation. Validation happens at the call sites that create rows.
    ip_address = models.CharField(max_length=50, unique=True, verbose_name='IP Address or Subnet')
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
    def is_blocked(cls, ip_address):
        """True if `ip_address` is exactly blocked OR falls within a CIDR
        block. Mirrors WhitelistedIP.is_whitelisted's matching idiom.
        """
        import ipaddress as iplib
        try:
            addr = iplib.ip_address(ip_address)
        except ValueError:
            return False
        if cls.objects.filter(ip_address=ip_address).exists():
            return True
        for entry in cls.objects.filter(ip_address__contains='/').values_list('ip_address', flat=True):
            try:
                if addr in iplib.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        return False

    @classmethod
    def _aggregate_subnet(cls, ip_address):
        """If the configured threshold of auto-blocked /32 entries share
        an IPv4 /24, replace them with a single /24 block. No-op for IPv6
        (v1) or when a whitelisted IP lives in the same /24.
        """
        import ipaddress as iplib
        try:
            addr = iplib.ip_address(ip_address)
        except ValueError:
            return False
        if not isinstance(addr, iplib.IPv4Address):
            return False

        app_settings = AppSettings.load()
        if not app_settings.autoblock_subnet_aggregation_enabled:
            return False
        threshold = app_settings.autoblock_subnet_threshold
        if threshold < 2:
            return False

        network = iplib.IPv4Network(f'{ip_address}/24', strict=False)
        cidr = str(network)

        # If a covering CIDR already exists, nothing to do
        if cls.objects.filter(ip_address=cidr).exists():
            return False

        # Skip if any whitelisted IP lives inside this /24 — operators
        # explicitly want those addresses reachable, even if neighbors
        # are noisy.
        for wl in WhitelistedIP.objects.values_list('ip_address', flat=True):
            try:
                if '/' in wl:
                    if iplib.ip_network(wl, strict=False).overlaps(network):
                        return False
                else:
                    if iplib.ip_address(wl) in network:
                        return False
            except ValueError:
                continue

        # Find auto-blocked /32s in this /24. Regex anchors to the exact
        # three-octet prefix so 192.168.1.x doesn't match 192.168.10.x.
        prefix = '.'.join(str(network.network_address).split('.')[:3])
        candidates = cls.objects.filter(
            ip_address__regex=r'^' + prefix.replace('.', r'\.') + r'\.\d+$',
            auto_blocked=True,
        )
        ips_in_subnet = []
        for entry_ip in candidates.values_list('ip_address', flat=True):
            try:
                if iplib.ip_address(entry_ip) in network:
                    ips_in_subnet.append(entry_ip)
            except ValueError:
                continue

        if len(ips_in_subnet) < threshold:
            return False

        from django.db import transaction
        with transaction.atomic():
            cls.objects.filter(ip_address__in=ips_in_subnet).delete()
            cls.objects.create(
                ip_address=cidr,
                reason=f'Auto-blocked: aggregated {len(ips_in_subnet)} /32 hits in {cidr}',
                auto_blocked=True,
                expires_at=None,
            )
        return True

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

        try:
            ExtDynLists.sync_system_blocklist()
        except Exception:
            pass  # don't let an EDL sync hiccup break the nginx blocklist write

    # Path patterns that indicate scanner / exploit probing — any single hit
    # blocks the source IP immediately, regardless of rate. These are paths a
    # legitimate user has zero reason to ever request. Substrings are matched
    # case-insensitively against the URL path. Add only signals you're confident
    # carry no false positives — operator complaints about over-blocking belong
    # higher in the priority queue than missing a scanner.
    SCANNER_PATH_PATTERNS = (
        # Secrets & dotfiles
        '.env',
        '.git/',
        '.aws/',
        '.htpasswd',
        '.boto',
        '.pgpass',
        '.npmrc',
        '.netrc',
        '.streamlit/secrets',
        '.composer/auth',
        '.docker/config.json',
        'serviceaccountkey',
        'credentials.json',
        'id_rsa',
        # WordPress probing
        'wp-admin',
        'wp-login',
        'wp-content/plugins',
        'wp-config.php',
        'wp-json/',
        'wlwmanifest',
        'xmlrpc.php',
        # PHP info / generic probes (KL is Django — customers don't serve PHP)
        'phpinfo.php',
        'info.php',
        'php.php',
        'test.php',
        'debug.php',
        'phpversion.php',
        'configuration.php',
        'phpmyadmin',
        'eval-stdin.php',
        'vendor/phpunit',
        # OS / server files
        '/etc/passwd',
        '/etc/shadow',
        '/proc/self/environ',
        'server-status',
        'web.config',
        '/cgi-bin/',
        'sftp-config',
        # Framework / app exploits
        'actuator/env',
        '_ignition/',
        '__debug__/execute',
        '/@fs/',
        'database.yml',
        # Exchange / OWA
        '/owa/',
        '/ecp/',
        'autodiscover.xml',
    )

    @classmethod
    def _matched_scanner_pattern(cls, path, extra_patterns=()):
        """Return (pattern, is_custom) on match, else None.

        Custom (operator-added) patterns are checked first so a custom
        override can flag a path before the built-in tuple does.
        """
        if not path:
            return None
        lower = path.lower()
        for pat in extra_patterns:
            if pat in lower:
                return (pat, True)
        for pat in cls.SCANNER_PATH_PATTERNS:
            if pat in lower:
                return (pat, False)
        return None

    @classmethod
    def check_scanner_pattern_block(cls, ip_address, path):
        """Immediately block an IP that hits a known scanner/exploit path.

        Gated by the same `autoblock_enabled` master switch as the rate-based
        check. Returns True if a block was created, False otherwise.
        """
        if not ip_address:
            return False
        if not is_globally_blockable(ip_address):
            return False
        app_settings = AppSettings.load()
        if not app_settings.autoblock_enabled:
            return False
        if WhitelistedIP.is_whitelisted(ip_address):
            return False
        if cls.is_blocked(ip_address):
            return False

        match = cls._matched_scanner_pattern(path, app_settings.get_custom_scanner_patterns())
        if not match:
            return False
        pattern, is_custom = match

        from django.utils import timezone
        from datetime import timedelta
        expires = None
        if app_settings.autoblock_duration_minutes > 0:
            expires = timezone.now() + timedelta(minutes=app_settings.autoblock_duration_minutes)

        source = ' (custom)' if is_custom else ''
        cls.objects.create(
            ip_address=ip_address,
            reason=f'Auto-blocked: scanner pattern "{pattern}"{source} in {path[:120]}',
            auto_blocked=True,
            expires_at=expires,
        )
        cls._aggregate_subnet(ip_address)
        cls.sync_to_nginx()
        return True

    @classmethod
    def check_autoblock(cls, ip_address):
        """Check if an IP should be auto-blocked based on threshold settings.

        Two independent windows are evaluated:
          * Burst window (seconds, e.g. 50 hits in 60s) catches noisy scanners.
          * Cumulative window (hours, e.g. 30 hits in 24h) catches paced
            scanners that pace probes to stay under the burst threshold.
        """
        from django.utils import timezone
        from datetime import timedelta

        if not is_globally_blockable(ip_address):
            return False
        app_settings = AppSettings.load()
        if not app_settings.autoblock_enabled:
            return False

        if WhitelistedIP.is_whitelisted(ip_address):
            return False
        if cls.is_blocked(ip_address):
            return False

        actions = ['not_found', 'edl_not_found', 'edl_access']
        now = timezone.now()
        expires = None
        if app_settings.autoblock_duration_minutes > 0:
            expires = now + timedelta(minutes=app_settings.autoblock_duration_minutes)

        # Burst window
        burst_start = now - timedelta(seconds=app_settings.autoblock_window_seconds)
        burst_count = ActivityLog.objects.filter(
            ip_address=ip_address, action__in=actions, created_at__gte=burst_start,
        ).count()
        if burst_count >= app_settings.autoblock_threshold:
            cls.objects.create(
                ip_address=ip_address,
                reason=f'Auto-blocked: {burst_count} hits in {app_settings.autoblock_window_seconds}s',
                auto_blocked=True,
                expires_at=expires,
            )
            cls._aggregate_subnet(ip_address)
            cls.sync_to_nginx()
            return True

        # Cumulative-window (slow-probe) check
        if app_settings.autoblock_long_threshold > 0 and app_settings.autoblock_long_window_hours > 0:
            long_start = now - timedelta(hours=app_settings.autoblock_long_window_hours)
            long_count = ActivityLog.objects.filter(
                ip_address=ip_address, action__in=actions, created_at__gte=long_start,
            ).count()
            if long_count >= app_settings.autoblock_long_threshold:
                cls.objects.create(
                    ip_address=ip_address,
                    reason=f'Auto-blocked: {long_count} hits in {app_settings.autoblock_long_window_hours}h (slow-probe)',
                    auto_blocked=True,
                    expires_at=expires,
                )
                cls._aggregate_subnet(ip_address)
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
        if not is_globally_blockable(ip_address):
            return None
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


# Schemes a shortened link is allowed to point at. This is an allowlist on
# purpose: a public redirector must never forward to javascript:, data:,
# file:, etc. — those are phishing/XSS vectors. Web links + the "contact"
# schemes (mailto/tel) cover the real use cases. Kept here as the single
# source of truth, reused by both the field validator and the redirect
# response class in views.py.
ALLOWED_LINK_SCHEMES = ('http', 'https', 'ftp', 'ftps', 'mailto', 'tel')


def validate_short_link(value):
    """Validate the target of a shortened URL.

    Django's URLField/URLValidator hardcodes ``scheme://`` in its regex and
    rejects opaque-scheme URIs like ``mailto:`` and ``tel:`` outright, so we
    can't just widen its scheme list. Instead we dispatch by scheme:
    mailto/tel are validated loosely as opaque URIs, everything else goes
    through the standard URLValidator restricted to our web schemes.
    """
    from urllib.parse import urlparse
    from django.core.validators import URLValidator, EmailValidator
    from django.core.exceptions import ValidationError

    scheme = urlparse(value).scheme.lower()
    if scheme not in ALLOWED_LINK_SCHEMES:
        raise ValidationError(
            'Unsupported link type. Allowed: %(schemes)s.',
            params={'schemes': ', '.join(ALLOWED_LINK_SCHEMES)},
            code='invalid_scheme',
        )

    if scheme == 'mailto':
        # mailto:addr[,addr...][?query] — validate the address portion(s).
        addresses = value[len('mailto:'):].split('?', 1)[0]
        email_validator = EmailValidator(message='Enter a valid email address after mailto:.')
        for addr in filter(None, (a.strip() for a in addresses.split(','))):
            email_validator(addr)
        return

    if scheme == 'tel':
        return  # opaque; phone-number shapes vary too much to validate strictly

    URLValidator(schemes=['http', 'https', 'ftp', 'ftps'])(value)


class ShortenedURL(models.Model):
    title = models.CharField(max_length=255, blank=True, default='', db_default='', verbose_name='Title')
    original_url = models.CharField(max_length=2048, validators=[validate_short_link], verbose_name='Original URL')
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

    MODE_SECURE = 'secure'
    MODE_CASUAL = 'casual'
    MODE_CHOICES = [
        (MODE_SECURE, 'Secure'),
        (MODE_CASUAL, 'Casual'),
    ]

    file = models.FileField(upload_to='otf/', verbose_name='File')
    original_filename = models.CharField(max_length=500, verbose_name='Original Filename')
    token = models.CharField(max_length=64, unique=True, blank=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='uploaded_files')
    recipient_email = models.EmailField(verbose_name='Recipient Email')
    mode = models.CharField(max_length=10, choices=MODE_CHOICES, default=MODE_SECURE, db_default=MODE_SECURE)
    max_downloads = models.PositiveIntegerField(default=1, db_default=1)
    casual_token = models.CharField(max_length=64, unique=True, null=True, blank=True)
    send_email = models.BooleanField(default=True, db_default=True)
    intended_recipients = models.JSONField(default=list, blank=True)
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
        if self.mode == self.MODE_CASUAL and not self.casual_token:
            self.casual_token = secrets.token_urlsafe(32) + ".kl"
        if not self.expires_at:
            from django.utils import timezone
            from datetime import timedelta
            self.expires_at = timezone.now() + timedelta(hours=self.expiry_hours)
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
        return not self.burned and not self.is_expired

    def burn_disk(self):
        """Delete the file from disk and mark burned. Audit rows kept."""
        from django.utils import timezone
        self.burned = True
        if self.downloaded and not self.downloaded_at:
            self.downloaded_at = timezone.now()
        self.save(update_fields=['burned', 'downloaded_at'])
        if self.file:
            try:
                self.file.delete(save=False)
            except Exception:
                pass

    # Legacy alias; older callers (e.g. otf_delete_view) expect .burn()
    def burn(self):
        self.burn_disk()


def _otf_generate_otp(obj):
    import random
    from django.utils import timezone
    obj.otp = f'{random.randint(100000, 999999)}'
    obj.otp_created_at = timezone.now()
    obj.save(update_fields=['otp', 'otp_created_at'])
    return obj.otp


def _otf_verify_otp(obj, code):
    from django.utils import timezone
    from datetime import timedelta
    if not obj.otp or not obj.otp_created_at:
        return False
    if timezone.now() > obj.otp_created_at + timedelta(minutes=5):
        return False
    return obj.otp == (code or '').strip()


class OTFRecipient(models.Model):
    """A pre-set recipient on a secure-mode OneTimeFile. Has its own URL token and single-use burn state."""
    file = models.ForeignKey(OneTimeFile, on_delete=models.CASCADE, related_name='recipients')
    email = models.EmailField()
    token = models.CharField(max_length=64, unique=True, blank=True)
    otp = models.CharField(max_length=6, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    downloaded = models.BooleanField(default=False)
    downloaded_at = models.DateTimeField(null=True, blank=True)
    burned = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [('file', 'email')]
        ordering = ['created_at']

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(32) + ".kl"
        super().save(*args, **kwargs)

    def generate_otp(self):
        return _otf_generate_otp(self)

    def verify_otp(self, code):
        return _otf_verify_otp(self, code)

    def __str__(self):
        return f"{self.email} ({self.token[:8]}...)"


class OTFSession(models.Model):
    """A self-attested email on a casual-mode OneTimeFile. One row per (file, email)."""
    file = models.ForeignKey(OneTimeFile, on_delete=models.CASCADE, related_name='sessions')
    email = models.EmailField()
    otp = models.CharField(max_length=6, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    download_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [('file', 'email')]
        ordering = ['created_at']

    def generate_otp(self):
        return _otf_generate_otp(self)

    def verify_otp(self, code):
        return _otf_verify_otp(self, code)

    def __str__(self):
        return f"{self.email} ({self.download_count} downloads)"


class OTFDownload(models.Model):
    """Per-delivery audit row. Set either recipient (secure) or session (casual)."""
    file = models.ForeignKey(OneTimeFile, on_delete=models.CASCADE, related_name='downloads')
    recipient = models.ForeignKey(OTFRecipient, on_delete=models.SET_NULL, null=True, blank=True, related_name='downloads')
    session = models.ForeignKey(OTFSession, on_delete=models.SET_NULL, null=True, blank=True, related_name='downloads')
    email = models.EmailField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.email} @ {self.created_at:%Y-%m-%d %H:%M}"


class OneTimeSecret(models.Model):
    """A secure-mode, single-reveal text secret. Sibling of OneTimeFile.

    The payload lives encrypted in the DB (no file on disk). Each recipient gets
    a unique link gated by an emailed OTP; revealing burns that recipient. Once
    every recipient has read it (or it expires), the plaintext is scrubbed.
    """
    EXPIRY_CHOICES = OneTimeFile.EXPIRY_CHOICES

    label = models.CharField(max_length=255, verbose_name='Label')
    secret_text = EncryptedTextField(blank=True, default='', verbose_name='Secret')
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_secrets')
    recipient_email = models.EmailField(verbose_name='Recipient Email')
    send_email = models.BooleanField(default=True, db_default=True)
    expiry_hours = models.PositiveIntegerField(default=24, choices=EXPIRY_CHOICES, verbose_name='Expires After')
    expires_at = models.DateTimeField(verbose_name='Expires At')
    revealed = models.BooleanField(default=False)
    revealed_at = models.DateTimeField(null=True, blank=True)
    burned = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "One-Time Secret"
        verbose_name_plural = "One-Time Secrets"
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if not self.expires_at:
            from django.utils import timezone
            from datetime import timedelta
            self.expires_at = timezone.now() + timedelta(hours=self.expiry_hours)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.label} ({self.recipient_email})"

    @property
    def is_expired(self):
        from django.utils import timezone
        return timezone.now() >= self.expires_at

    @property
    def is_available(self):
        return not self.burned and not self.is_expired

    def burn(self):
        """Scrub the plaintext and mark burned. Audit rows are kept.

        Unlike OneTimeFile (which deletes a file from disk), the secret itself
        lives in this row, so burning must null out secret_text so no recoverable
        ciphertext remains.
        """
        from django.utils import timezone
        self.burned = True
        self.secret_text = ''
        if self.revealed and not self.revealed_at:
            self.revealed_at = timezone.now()
        self.save(update_fields=['burned', 'secret_text', 'revealed_at'])


class OTSRecipient(models.Model):
    """A pre-set recipient on a OneTimeSecret. Has its own URL token and single-use burn state."""
    secret = models.ForeignKey(OneTimeSecret, on_delete=models.CASCADE, related_name='recipients')
    email = models.EmailField()
    token = models.CharField(max_length=64, unique=True, blank=True)
    otp = models.CharField(max_length=6, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    revealed = models.BooleanField(default=False)
    revealed_at = models.DateTimeField(null=True, blank=True)
    burned = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [('secret', 'email')]
        ordering = ['created_at']

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(32) + ".kl"
        super().save(*args, **kwargs)

    def generate_otp(self):
        return _otf_generate_otp(self)

    def verify_otp(self, code):
        return _otf_verify_otp(self, code)

    def __str__(self):
        return f"{self.email} ({self.token[:8]}...)"


class OTSAccess(models.Model):
    """Per-reveal audit row for a OneTimeSecret."""
    secret = models.ForeignKey(OneTimeSecret, on_delete=models.CASCADE, related_name='accesses')
    recipient = models.ForeignKey(OTSRecipient, on_delete=models.SET_NULL, null=True, blank=True, related_name='accesses')
    email = models.EmailField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.email} @ {self.created_at:%Y-%m-%d %H:%M}"


class Paste(models.Model):
    """An unlisted, link-shared text/code snippet. Body is encrypted at rest.

    Reachable by anyone holding the /p/<code>/ link; viewable repeatedly until an
    optional expiry. Unlike OTF/OTS there is no burn and no OTP gate.
    """
    # Reuse the OTF expiry tiers, plus a "Never" option (expires_at stays null).
    EXPIRY_NEVER = 0
    EXPIRY_CHOICES = [(EXPIRY_NEVER, 'Never')] + list(OneTimeFile.EXPIRY_CHOICES)

    # Hard cap so an encrypted blob can't grow unbounded (bytes of UTF-8 body).
    MAX_BODY_BYTES = 512 * 1024

    title = models.CharField(max_length=255, blank=True, default='', verbose_name='Title')
    body = EncryptedTextField(verbose_name='Content')
    language = models.CharField(max_length=32, default='auto', blank=True, verbose_name='Language')
    code = models.CharField(max_length=64, unique=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='pastes')
    expiry_hours = models.PositiveIntegerField(default=EXPIRY_NEVER, choices=EXPIRY_CHOICES, verbose_name='Expires After')
    expires_at = models.DateTimeField(null=True, blank=True, verbose_name='Expires At')
    view_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Paste"
        verbose_name_plural = "Pastes"
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if not self.code:
            self.code = secrets.token_urlsafe(8) + ".kl"
        if self.expiry_hours and self.expiry_hours != self.EXPIRY_NEVER:
            from django.utils import timezone
            from datetime import timedelta
            self.expires_at = timezone.now() + timedelta(hours=self.expiry_hours)
        else:
            self.expires_at = None
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.title or '(untitled)'} ({self.code[:8]}...)"

    @property
    def is_expired(self):
        if self.expires_at is None:
            return False
        from django.utils import timezone
        return timezone.now() >= self.expires_at

    @property
    def is_available(self):
        return not self.is_expired


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