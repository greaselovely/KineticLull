"""
Management command to parse Nginx access logs for 403 rejections.
Stores results in the NginxRejection model for display in the UI.

Usage:
    python manage.py parse_nginx_rejections
    python manage.py parse_nginx_rejections --log-path /var/log/nginx/access.log
    python manage.py parse_nginx_rejections --purge-days 30

Recommended cron (every 5 minutes):
    */5 * * * * cd /path/to/KineticLull && venv/bin/python manage.py parse_nginx_rejections
"""

import re
from datetime import datetime, timezone
from pathlib import Path

from django.core.management.base import BaseCommand
from django.conf import settings

from app.models import NginxRejection


# Nginx combined log format:
# 10.1.1.2 - - [31/Mar/2026:17:19:51 +0000] "GET /info.php HTTP/1.1" 403 162 "-" "Mozilla/5.0"
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+'
)

NGINX_TIME_FORMAT = '%d/%b/%Y:%H:%M:%S %z'

# State file to track last parsed position
STATE_FILE_NAME = '.nginx_parse_state'


class Command(BaseCommand):
    help = 'Parse Nginx access log for 403 rejections and store in the database.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--log-path',
            default='/var/log/nginx/access.log',
            help='Path to Nginx access log (default: /var/log/nginx/access.log)',
        )
        parser.add_argument(
            '--purge-days',
            type=int,
            default=30,
            help='Delete rejection records older than N days (default: 30)',
        )

    def handle(self, *args, **options):
        log_path = Path(options['log_path'])
        purge_days = options['purge_days']
        state_path = Path(settings.BASE_DIR) / STATE_FILE_NAME

        if not log_path.exists():
            self.stdout.write(self.style.WARNING(f'Log file not found: {log_path}'))
            return

        # Read last parsed position (inode + offset) to avoid re-parsing
        last_inode = 0
        last_offset = 0
        if state_path.exists():
            try:
                parts = state_path.read_text().strip().split(':')
                last_inode = int(parts[0])
                last_offset = int(parts[1])
            except (ValueError, IndexError):
                pass

        # Check if log file was rotated (inode changed)
        current_inode = log_path.stat().st_ino
        if current_inode != last_inode:
            last_offset = 0

        # Parse new lines
        rejections = []
        new_offset = last_offset

        with open(log_path, 'r') as f:
            f.seek(last_offset)
            for line in f:
                match = LOG_PATTERN.match(line)
                if match and match.group('status') == '403':
                    try:
                        ts = datetime.strptime(match.group('timestamp'), NGINX_TIME_FORMAT)
                        rejections.append(NginxRejection(
                            ip_address=match.group('ip'),
                            path=match.group('path')[:500],
                            timestamp=ts,
                        ))
                    except (ValueError, KeyError):
                        continue
            new_offset = f.tell()

        # Bulk insert
        if rejections:
            NginxRejection.objects.bulk_create(rejections, ignore_conflicts=True)
            self.stdout.write(self.style.SUCCESS(f'Stored {len(rejections)} rejections.'))
        else:
            self.stdout.write('No new 403 rejections found.')

        # Save state
        state_path.write_text(f'{current_inode}:{new_offset}')

        # Purge old records
        NginxRejection.purge_old(days=purge_days)
