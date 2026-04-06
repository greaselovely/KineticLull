"""
Management command to restore EDLs and shortened URLs from a backup archive.
Restores with exact same auto_url/short_code so external references don't break.

Usage:
    python manage.py restore_data backup_20260406120000.tar.gz
"""

import os
import json
import tarfile
import tempfile
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Restore EDLs and shortened URLs from a backup archive'

    def add_arguments(self, parser):
        parser.add_argument('archive', type=str, help='Backup archive filename (in backups/data/)')

    def handle(self, *args, **options):
        from app.models import ExtDynLists, ShortenedURL
        from users.models import CustomUser
        from django.contrib.auth.models import Group

        backup_dir = Path(settings.BASE_DIR) / 'backups' / 'data'
        archive_path = backup_dir / options['archive']

        if not archive_path.exists():
            raise CommandError(f'Archive not found: {archive_path}')

        with tempfile.TemporaryDirectory() as tmpdir:
            with tarfile.open(archive_path, 'r:gz') as tar:
                tar.extractall(tmpdir)

            # Restore EDLs
            edl_path = os.path.join(tmpdir, 'edls.txt')
            if os.path.exists(edl_path):
                edl_count = 0
                with open(edl_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        record = json.loads(line)

                        # Check if EDL with same auto_url already exists
                        existing = ExtDynLists.objects.filter(auto_url=record['auto_url']).first()
                        if existing:
                            # Update existing
                            existing.friendly_name = record['friendly_name']
                            existing.ip_fqdn = record['ip_fqdn']
                            existing.acl = record['acl']
                            existing.policy_reference = record['policy_reference']
                            existing.save()
                            self.stdout.write(f'  Updated EDL: {record["friendly_name"]} ({record["auto_url"]})')
                        else:
                            # Create with exact auto_url
                            edl = ExtDynLists(
                                friendly_name=record['friendly_name'],
                                auto_url=record['auto_url'],
                                ip_fqdn=record['ip_fqdn'],
                                acl=record['acl'],
                                policy_reference=record['policy_reference'],
                            )
                            edl.save()
                            # Restore group associations
                            if record.get('groups'):
                                groups = Group.objects.filter(name__in=record['groups'])
                                edl.groups.set(groups)
                            self.stdout.write(f'  Restored EDL: {record["friendly_name"]} ({record["auto_url"]})')
                        edl_count += 1
                self.stdout.write(f'EDLs processed: {edl_count}')

            # Restore shortened URLs
            url_path = os.path.join(tmpdir, 'urls.txt')
            if os.path.exists(url_path):
                url_count = 0
                with open(url_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        record = json.loads(line)

                        existing = ShortenedURL.objects.filter(short_code=record['short_code']).first()
                        if existing:
                            existing.original_url = record['original_url']
                            existing.notes = record.get('notes', '')
                            existing.hit_count = record.get('hit_count', 0)
                            existing.save()
                            self.stdout.write(f'  Updated URL: {record["short_code"]}')
                        else:
                            # Find the user to assign to
                            owner = None
                            if record.get('created_by_email'):
                                owner = CustomUser.objects.filter(email=record['created_by_email']).first()
                            if not owner:
                                owner = CustomUser.objects.order_by('date_joined').first()

                            url = ShortenedURL(
                                original_url=record['original_url'],
                                short_code=record['short_code'],
                                notes=record.get('notes', ''),
                                created_by=owner,
                                hit_count=record.get('hit_count', 0),
                            )
                            url.save()
                            self.stdout.write(f'  Restored URL: {record["short_code"]}')
                        url_count += 1
                self.stdout.write(f'URLs processed: {url_count}')

        self.stdout.write(self.style.SUCCESS(f'Restore complete from {options["archive"]}'))
