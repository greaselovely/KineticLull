"""
Management command to export EDLs and shortened URLs to gzipped text files.
Retains 30 days of backups, auto-removes older archives.

Usage:
    python manage.py backup_data

Each backup creates a timestamped .tar.gz in backups/data/ containing:
    - edls.txt: all EDL fields, one JSON object per line
    - urls.txt: all shortened URL fields, one JSON object per line
"""

import os
import json
import gzip
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Export EDLs and shortened URLs to a gzipped backup archive'

    def handle(self, *args, **options):
        from app.models import ExtDynLists, ShortenedURL

        backup_dir = Path(settings.BASE_DIR) / 'backups' / 'data'
        backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        archive_name = f'backup_{timestamp}.tar.gz'
        archive_path = backup_dir / archive_name

        base_url = getattr(settings, 'KINETICLULL_URL', os.environ.get('KINETICLULL_URL', 'http://127.0.0.1:8000'))

        with tempfile.TemporaryDirectory() as tmpdir:
            # Export EDLs
            edl_path = os.path.join(tmpdir, 'edls.txt')
            with open(edl_path, 'w') as f:
                for edl in ExtDynLists.objects.all():
                    full_url = base_url + ('/' if not edl.auto_url.startswith('/') else '') + edl.auto_url
                    record = {
                        'id': edl.id,
                        'friendly_name': edl.friendly_name,
                        'auto_url': edl.auto_url,
                        'full_url': full_url,
                        'ip_fqdn': edl.ip_fqdn,
                        'acl': edl.acl,
                        'policy_reference': edl.policy_reference,
                        'groups': list(edl.groups.values_list('name', flat=True)),
                        'created_date': edl.created_date.isoformat() if edl.created_date else None,
                    }
                    f.write(json.dumps(record) + '\n')

            # Export shortened URLs
            url_path = os.path.join(tmpdir, 'urls.txt')
            with open(url_path, 'w') as f:
                for url in ShortenedURL.objects.all():
                    short_url = f'{base_url}/s/{url.short_code}'
                    record = {
                        'id': url.id,
                        'original_url': url.original_url,
                        'short_code': url.short_code,
                        'short_url': short_url,
                        'notes': url.notes,
                        'created_by_email': url.created_by.email if url.created_by else None,
                        'hit_count': url.hit_count,
                        'created_at': url.created_at.isoformat() if url.created_at else None,
                    }
                    f.write(json.dumps(record) + '\n')

            # Create tar.gz
            with tarfile.open(archive_path, 'w:gz') as tar:
                tar.add(edl_path, arcname='edls.txt')
                tar.add(url_path, arcname='urls.txt')

        self.stdout.write(f'Backup created: {archive_path}')

        # Purge backups older than 30 days
        cutoff = datetime.now().timestamp() - (30 * 86400)
        for f in backup_dir.glob('backup_*.tar.gz'):
            if f.stat().st_mtime < cutoff:
                f.unlink()
                self.stdout.write(f'Purged old backup: {f.name}')
