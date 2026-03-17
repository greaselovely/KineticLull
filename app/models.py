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

    def __str__(self):
        return f"{self.created_at} {self.user} {self.action} {self.target}"


class AppSettings(models.Model):
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
    default_edl_per_page = models.PositiveIntegerField(default=5, verbose_name='Default EDLs per page')
    default_log_per_page = models.PositiveIntegerField(default=25, verbose_name='Default logs per page')
    edl_preview_entries = models.PositiveIntegerField(default=3, verbose_name='EDL preview entries on index')

    # API Limits
    max_fqdns_per_submission = models.PositiveIntegerField(default=50, verbose_name='Max FQDNs per API submission')
    max_fqdns_per_update = models.PositiveIntegerField(default=50, verbose_name='Max FQDNs per API update')

    # Data Limits
    max_edls_per_group = models.PositiveIntegerField(default=0, verbose_name='Max EDLs per group (0=unlimited)')
    max_entries_per_edl = models.PositiveIntegerField(default=0, verbose_name='Max entries per EDL (0=unlimited)')
    max_inbox_per_user = models.PositiveIntegerField(default=0, verbose_name='Max inbox entries per user (0=unlimited)')

    # Retention
    log_retention_days = models.PositiveIntegerField(default=90, verbose_name='Log retention (days, max 180)')

    # Security
    session_timeout_minutes = models.PositiveIntegerField(default=30, verbose_name='Session timeout (minutes)')
    api_key_expiration_days = models.PositiveIntegerField(default=90, verbose_name='API key expiration (days, 14-365)')

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