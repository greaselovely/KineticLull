"""
Management command to restore from a backup archive.
Handles both v2 (full) and legacy v1 (edls.txt/urls.txt) archives.

Usage:
    python manage.py restore_data backup_20260406120000.tar.gz
"""

import os
import json
import shutil
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils.dateparse import parse_datetime


def _parse_dt(value):
    return parse_datetime(value) if value else None


class Command(BaseCommand):
    help = 'Restore from a backup archive (users, EDLs, URLs, OTFs, settings, etc.)'

    def add_arguments(self, parser):
        parser.add_argument('archive', type=str, help='Backup archive filename (in backups/data/)')

    def handle(self, *args, **options):
        backup_dir = Path(settings.BASE_DIR) / 'backups' / 'data'
        archive_path = backup_dir / options['archive']

        if not archive_path.exists():
            raise CommandError(f'Archive not found: {archive_path}')

        with tempfile.TemporaryDirectory() as tmpdir:
            with tarfile.open(archive_path, 'r:gz') as tar:
                tar.extractall(tmpdir)

            data_json = os.path.join(tmpdir, 'data.json')
            if os.path.exists(data_json):
                self._restore_v2(tmpdir, data_json)
            else:
                self._restore_v1_legacy(tmpdir)

        self.stdout.write(self.style.SUCCESS(f'Restore complete from {options["archive"]}'))

    def _restore_v2(self, tmpdir, data_json_path):
        from app.models import (
            ExtDynLists, ShortenedURL, OneTimeFile, Favorite,
            BlockedIP, WhitelistedIP, AppSettings,
        )
        from users.models import CustomUser, APIKey
        from django.contrib.auth.models import Group

        with open(data_json_path) as f:
            data = json.load(f)

        # Groups (create any missing — permissions are re-synced by apps.ready())
        for name in data.get('groups', []):
            Group.objects.get_or_create(name=name)
            self.stdout.write(f'  Group: {name}')

        # Users (upsert by email, preserve password hash)
        for u in data.get('users', []):
            user, _created = CustomUser.objects.update_or_create(
                email=u['email'],
                defaults={
                    'first_name': u.get('first_name', ''),
                    'last_name': u.get('last_name', ''),
                    'password': u['password'],
                    'is_staff': u.get('is_staff', False),
                    'is_active': u.get('is_active', True),
                    'is_superuser': u.get('is_superuser', False),
                    'date_joined': _parse_dt(u.get('date_joined')) or datetime.now(),
                    'last_login': _parse_dt(u.get('last_login')),
                },
            )
            if u.get('groups'):
                groups = Group.objects.filter(name__in=u['groups'])
                user.groups.set(groups)
            self.stdout.write(f'  User: {u["email"]}')

        # API keys
        for k in data.get('api_keys', []):
            owner = CustomUser.objects.filter(email=k['user_email']).first()
            if not owner:
                continue
            APIKey.objects.update_or_create(
                key=k['key'],
                defaults={
                    'user': owner,
                    'expires_at': _parse_dt(k.get('expires_at')),
                },
            )
            self.stdout.write(f'  API key for: {k["user_email"]}')

        # EDLs
        for e in data.get('edls', []):
            existing = ExtDynLists.objects.filter(auto_url=e['auto_url']).first()
            if existing:
                existing.friendly_name = e['friendly_name']
                existing.ip_fqdn = e['ip_fqdn']
                existing.acl = e['acl']
                existing.policy_reference = e['policy_reference']
                existing.save()
                edl = existing
            else:
                edl = ExtDynLists.objects.create(
                    friendly_name=e['friendly_name'],
                    auto_url=e['auto_url'],
                    ip_fqdn=e['ip_fqdn'],
                    acl=e['acl'],
                    policy_reference=e['policy_reference'],
                )
            if e.get('groups'):
                edl.groups.set(Group.objects.filter(name__in=e['groups']))
            self.stdout.write(f'  EDL: {e["friendly_name"]}')

        # Shortened URLs
        for s in data.get('shortened_urls', []):
            owner = None
            if s.get('created_by_email'):
                owner = CustomUser.objects.filter(email=s['created_by_email']).first()
            if not owner:
                owner = CustomUser.objects.order_by('date_joined').first()
            if not owner:
                self.stdout.write(self.style.WARNING(f'  Skipped URL {s["short_code"]}: no user exists to own it'))
                continue
            ShortenedURL.objects.update_or_create(
                short_code=s['short_code'],
                defaults={
                    'title': s.get('title', ''),
                    'original_url': s['original_url'],
                    'notes': s.get('notes', ''),
                    'created_by': owner,
                    'hit_count': s.get('hit_count', 0),
                },
            )
            self.stdout.write(f'  URL: {s["short_code"]}')

        # Restore media files (OTF uploads + branding) BEFORE OTF records,
        # so the FileField references point to files that actually exist.
        media_src = os.path.join(tmpdir, 'media')
        if os.path.isdir(media_src):
            media_dest = Path(settings.MEDIA_ROOT)
            media_dest.mkdir(parents=True, exist_ok=True)
            for sub in os.listdir(media_src):
                src = os.path.join(media_src, sub)
                dst = media_dest / sub
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                    self.stdout.write(f'  Media: {sub}/')

        # OneTimeFile records
        for o in data.get('one_time_files', []):
            owner = None
            if o.get('uploaded_by_email'):
                owner = CustomUser.objects.filter(email=o['uploaded_by_email']).first()
            OneTimeFile.objects.update_or_create(
                token=o['token'],
                defaults={
                    'file': o['file_path'],
                    'original_filename': o['original_filename'],
                    'uploaded_by': owner,
                    'recipient_email': o['recipient_email'],
                    'expiry_hours': o.get('expiry_hours', 24),
                    'expires_at': _parse_dt(o.get('expires_at')) or datetime.now(),
                    'downloaded': o.get('downloaded', False),
                    'downloaded_at': _parse_dt(o.get('downloaded_at')),
                    'burned': o.get('burned', False),
                },
            )
            self.stdout.write(f'  OTF: {o["original_filename"]}')

        # Favorites
        for fav in data.get('favorites', []):
            user = CustomUser.objects.filter(email=fav['user_email']).first()
            edl = ExtDynLists.objects.filter(auto_url=fav['edl_auto_url']).first()
            if user and edl:
                Favorite.objects.get_or_create(user=user, edl=edl)

        # Blocked IPs
        for b in data.get('blocked_ips', []):
            blocker = None
            if b.get('blocked_by_email'):
                blocker = CustomUser.objects.filter(email=b['blocked_by_email']).first()
            BlockedIP.objects.update_or_create(
                ip_address=b['ip_address'],
                defaults={
                    'reason': b.get('reason', ''),
                    'blocked_by': blocker,
                    'auto_blocked': b.get('auto_blocked', False),
                    'expires_at': _parse_dt(b.get('expires_at')),
                },
            )

        # Whitelisted IPs
        for w in data.get('whitelisted_ips', []):
            adder = None
            if w.get('added_by_email'):
                adder = CustomUser.objects.filter(email=w['added_by_email']).first()
            WhitelistedIP.objects.update_or_create(
                ip_address=w['ip_address'],
                defaults={
                    'reason': w.get('reason', ''),
                    'added_by': adder,
                },
            )

        # AppSettings (singleton — update fields in place)
        app_settings_data = data.get('app_settings')
        if app_settings_data:
            s = AppSettings.load()
            for name, value in app_settings_data.items():
                if not hasattr(s, name):
                    continue
                field = s._meta.get_field(name)
                if field.get_internal_type() in ('DateTimeField', 'DateField'):
                    value = _parse_dt(value) if value else None
                try:
                    setattr(s, name, value)
                except Exception:
                    pass
            s.save()
            self.stdout.write('  App settings restored')

        # Resync nginx blocklist file
        try:
            BlockedIP.sync_to_nginx()
        except Exception:
            pass

    def _restore_v1_legacy(self, tmpdir):
        """Handle the old format: edls.txt + urls.txt (JSON-per-line)."""
        from app.models import ExtDynLists, ShortenedURL
        from users.models import CustomUser
        from django.contrib.auth.models import Group

        edl_path = os.path.join(tmpdir, 'edls.txt')
        if os.path.exists(edl_path):
            count = 0
            with open(edl_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    r = json.loads(line)
                    existing = ExtDynLists.objects.filter(auto_url=r['auto_url']).first()
                    if existing:
                        existing.friendly_name = r['friendly_name']
                        existing.ip_fqdn = r['ip_fqdn']
                        existing.acl = r['acl']
                        existing.policy_reference = r['policy_reference']
                        existing.save()
                        edl = existing
                    else:
                        edl = ExtDynLists.objects.create(
                            friendly_name=r['friendly_name'],
                            auto_url=r['auto_url'],
                            ip_fqdn=r['ip_fqdn'],
                            acl=r['acl'],
                            policy_reference=r['policy_reference'],
                        )
                    if r.get('groups'):
                        edl.groups.set(Group.objects.filter(name__in=r['groups']))
                    count += 1
            self.stdout.write(f'EDLs processed: {count}')

        url_path = os.path.join(tmpdir, 'urls.txt')
        if os.path.exists(url_path):
            count = 0
            with open(url_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    r = json.loads(line)
                    owner = None
                    if r.get('created_by_email'):
                        owner = CustomUser.objects.filter(email=r['created_by_email']).first()
                    if not owner:
                        owner = CustomUser.objects.order_by('date_joined').first()
                    if not owner:
                        continue
                    ShortenedURL.objects.update_or_create(
                        short_code=r['short_code'],
                        defaults={
                            'title': r.get('title', ''),
                            'original_url': r['original_url'],
                            'notes': r.get('notes', ''),
                            'created_by': owner,
                            'hit_count': r.get('hit_count', 0),
                        },
                    )
                    count += 1
            self.stdout.write(f'URLs processed: {count}')
