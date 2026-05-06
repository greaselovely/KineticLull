"""
Management command to export a full data backup.
Retains 30 days of backups, auto-removes older archives.

Usage:
    python manage.py backup_data

Each backup creates a timestamped .tar.gz in backups/data/ containing:
    - data.json: all model rows (users, groups, EDLs, URLs, OTF records, settings, etc.)
    - media/otf/: uploaded one-time files (as stored on disk)
"""

import os
import json
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db.models.fields.files import FieldFile

from app.crypto import EncryptedCharField, encrypt as _encrypt_secret


class Command(BaseCommand):
    help = 'Export a full data backup (users, EDLs, URLs, OTFs, settings, etc.)'

    def handle(self, *args, **options):
        from app.models import (
            ExtDynLists, ShortenedURL, OneTimeFile, Favorite,
            BlockedIP, WhitelistedIP, AppSettings,
        )
        from users.models import CustomUser, APIKey
        from django.contrib.auth.models import Group

        backup_dir = Path(settings.BASE_DIR) / 'backups' / 'data'
        backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        archive_name = f'backup_{timestamp}.tar.gz'
        archive_path = backup_dir / archive_name

        base_url = getattr(settings, 'KINETICLULL_URL', os.environ.get('KINETICLULL_URL', 'http://127.0.0.1:8000'))

        def iso(dt):
            return dt.isoformat() if dt else None

        data = {'backup_version': 2, 'created_at': datetime.now().isoformat(), 'base_url': base_url}

        # Groups
        data['groups'] = [g.name for g in Group.objects.all()]

        # Users (password hash preserved so logins survive)
        data['users'] = [{
            'email': u.email,
            'first_name': u.first_name,
            'last_name': u.last_name,
            'password': u.password,
            'is_staff': u.is_staff,
            'is_active': u.is_active,
            'is_superuser': u.is_superuser,
            'date_joined': iso(u.date_joined),
            'last_login': iso(u.last_login),
            'groups': list(u.groups.values_list('name', flat=True)),
        } for u in CustomUser.objects.all()]

        # API keys
        data['api_keys'] = [{
            'user_email': k.user.email,
            'key': k.key,
            'created_at': iso(k.created_at),
            'expires_at': iso(k.expires_at),
        } for k in APIKey.objects.select_related('user').all()]

        # EDLs
        data['edls'] = [{
            'friendly_name': e.friendly_name,
            'auto_url': e.auto_url,
            'ip_fqdn': e.ip_fqdn,
            'acl': e.acl,
            'policy_reference': e.policy_reference,
            'groups': list(e.groups.values_list('name', flat=True)),
            'created_date': iso(e.created_date),
        } for e in ExtDynLists.objects.all()]

        # Shortened URLs
        data['shortened_urls'] = [{
            'title': s.title,
            'original_url': s.original_url,
            'short_code': s.short_code,
            'notes': s.notes,
            'created_by_email': s.created_by.email if s.created_by else None,
            'hit_count': s.hit_count,
            'created_at': iso(s.created_at),
        } for s in ShortenedURL.objects.select_related('created_by').all()]

        # OneTimeFiles (record metadata — actual file bytes travel in the tar)
        data['one_time_files'] = [{
            'file_path': o.file.name,  # relative to MEDIA_ROOT, e.g. "otf/abc.bin"
            'original_filename': o.original_filename,
            'token': o.token,
            'uploaded_by_email': o.uploaded_by.email if o.uploaded_by else None,
            'recipient_email': o.recipient_email,
            'expiry_hours': o.expiry_hours,
            'expires_at': iso(o.expires_at),
            'downloaded': o.downloaded,
            'downloaded_at': iso(o.downloaded_at),
            'burned': o.burned,
            'created_at': iso(o.created_at),
        } for o in OneTimeFile.objects.select_related('uploaded_by').all()]

        # Favorites (by user email + EDL auto_url)
        data['favorites'] = [{
            'user_email': f.user.email,
            'edl_auto_url': f.edl.auto_url,
        } for f in Favorite.objects.select_related('user', 'edl').all()]

        # Blocked IPs
        data['blocked_ips'] = [{
            'ip_address': b.ip_address,
            'reason': b.reason,
            'blocked_at': iso(b.blocked_at),
            'blocked_by_email': b.blocked_by.email if b.blocked_by else None,
            'auto_blocked': b.auto_blocked,
            'expires_at': iso(b.expires_at),
        } for b in BlockedIP.objects.select_related('blocked_by').all()]

        # Whitelisted IPs
        data['whitelisted_ips'] = [{
            'ip_address': w.ip_address,
            'reason': w.reason,
            'added_by_email': w.added_by.email if w.added_by else None,
            'added_at': iso(w.added_at),
        } for w in WhitelistedIP.objects.select_related('added_by').all()]

        # AppSettings (singleton)
        s = AppSettings.load()
        settings_dict = {}
        for field in s._meta.fields:
            if field.name == 'id':
                continue
            value = getattr(s, field.name)
            if isinstance(field, EncryptedCharField):
                # Store ciphertext so the backup doesn't leak the plaintext secret.
                settings_dict[field.name] = _encrypt_secret(value or '')
            elif isinstance(value, FieldFile):
                settings_dict[field.name] = value.name or ''
            elif hasattr(value, 'isoformat'):
                settings_dict[field.name] = value.isoformat()
            else:
                settings_dict[field.name] = value
        data['app_settings'] = settings_dict

        # Write the tarball
        with tempfile.TemporaryDirectory() as tmpdir:
            data_path = os.path.join(tmpdir, 'data.json')
            with open(data_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)

            with tarfile.open(archive_path, 'w:gz') as tar:
                tar.add(data_path, arcname='data.json')
                # Include media/otf/ contents under media/otf/ inside the tar
                media_otf = Path(settings.MEDIA_ROOT) / 'otf'
                if media_otf.exists():
                    tar.add(str(media_otf), arcname='media/otf')
                # Branding logo if present
                branding = Path(settings.MEDIA_ROOT) / 'branding'
                if branding.exists():
                    tar.add(str(branding), arcname='media/branding')

        self.stdout.write(f'Backup created: {archive_path}')

        # Purge backups older than 30 days
        cutoff = datetime.now().timestamp() - (30 * 86400)
        for f in backup_dir.glob('backup_*.tar.gz'):
            if f.stat().st_mtime < cutoff:
                f.unlink()
                self.stdout.write(f'Purged old backup: {f.name}')
