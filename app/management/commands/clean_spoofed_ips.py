"""
Management command to clean spoofed / non-globally-routable IPs out of the
blocklist and rejection tables, and re-block the real attacker address.

Background
----------
Before the header-spoofing fix, get_client_ip() trusted the LEFTMOST
X-Forwarded-For token, which is fully attacker-controlled. Attackers sprayed
127.0.0.1 across every client-IP header (X-Forwarded-For, X-Client-IP,
True-Client-IP, X-Originating-IP, X-Azure-*, X-Host, ...) so that:
  * their real address never landed on the blocklist (block-evasion), and
  * a loopback address could be pushed into the firewall drop-EDL (outage risk).

This command undoes that damage on the host where KineticLull runs:
  1. Deletes BlockedIP + NginxRejection rows whose ip_address is NOT globally
     routable (loopback / RFC1918 / link-local / reserved / multicast).
  2. Recovers the TRUE client IP for each bogus BlockedIP by reading the
     x_real_ip= value that Nginx preserved in the ActivityLog `detail` field
     (falling back to the rightmost x_forwarded_for token), and re-blocks it.
  3. Re-syncs the Nginx blocklist file / system EDL.

ActivityLog is an immutable SHA256-chained audit trail and is NEVER modified
here — rewriting historical rows would (correctly) trip verify_chain(). The
recorded requests genuinely presented those spoofed headers; that is a true
fact worth keeping. We only recover the real IP from them.

Usage
-----
    python manage.py clean_spoofed_ips                 # dry-run report (default)
    python manage.py clean_spoofed_ips --commit        # delete bogus rows + re-block real IPs
    python manage.py clean_spoofed_ips --commit --no-reblock   # only delete, don't re-block
    python manage.py clean_spoofed_ips --commit --lookback-days 14
"""

import argparse
import ipaddress
import re

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

from app.models import (
    ActivityLog,
    BlockedIP,
    NginxRejection,
    WhitelistedIP,
    is_globally_blockable,
)

# Pull "x_real_ip=1.2.3.4" and "x_forwarded_for=a, b, c" out of the '; '-joined
# header dump stored in ActivityLog.detail (keys are lower-cased header names
# with HTTP_ stripped and '-' -> '_').
REAL_IP_RE = re.compile(r'x_real_ip=([^;]+)', re.IGNORECASE)
XFF_RE = re.compile(r'x_forwarded_for=([^;]+)', re.IGNORECASE)


def _is_non_global(value):
    """True if `value` is a valid IP that is NOT globally routable.

    CIDR blocks (e.g. an aggregated /24) are treated as global-or-not by their
    network address, so a private /24 is caught but a public one is left alone.
    """
    try:
        if '/' in value:
            net = ipaddress.ip_network(value, strict=False)
            return not net.network_address.is_global
        return not ipaddress.ip_address(value).is_global
    except ValueError:
        # Unparseable junk: treat as bogus so it gets cleaned out.
        return True


def _real_ip_from_detail(detail):
    """Recover the true client IP from a stored header dump.

    Prefers x_real_ip (set by Nginx from $remote_addr, unspoofable); falls
    back to the rightmost x_forwarded_for token (the one Nginx appended).
    Returns a globally-routable IP string, or None.
    """
    if not detail:
        return None

    m = REAL_IP_RE.search(detail)
    if m:
        candidate = m.group(1).strip()
        if is_globally_blockable(candidate):
            return candidate

    m = XFF_RE.search(detail)
    if m:
        for token in reversed([t.strip() for t in m.group(1).split(',')]):
            if is_globally_blockable(token):
                return token

    return None


class Command(BaseCommand):
    help = 'Remove spoofed/non-routable IPs from the blocklist and re-block the real attacker address.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--commit',
            action='store_true',
            help='Apply changes. Without this flag the command only reports (dry-run).',
        )
        parser.add_argument(
            '--reblock',
            action=argparse.BooleanOptionalAction,
            default=True,
            help='Re-block the recovered real attacker IP(s) (default: on). Use --no-reblock to skip.',
        )
        parser.add_argument(
            '--lookback-days',
            type=int,
            default=30,
            help='How far back to scan ActivityLog when recovering real IPs (default: 30).',
        )

    def handle(self, *args, **options):
        commit = options['commit']
        reblock = options['reblock']
        lookback = options['lookback_days']
        mode = 'COMMIT' if commit else 'DRY-RUN'

        self.stdout.write(self.style.MIGRATE_HEADING(f'clean_spoofed_ips ({mode})'))

        # --- 1. Identify bogus BlockedIP rows -----------------------------
        bogus_blocks = [b for b in BlockedIP.objects.all() if _is_non_global(b.ip_address)]
        bogus_rejections = [r for r in NginxRejection.objects.all() if _is_non_global(r.ip_address)]

        self.stdout.write('')
        self.stdout.write(f'Bogus BlockedIP entries:      {len(bogus_blocks)}')
        self.stdout.write(f'Bogus NginxRejection entries: {len(bogus_rejections)}')

        # --- 2. Recover real attacker IPs from the audit trail ------------
        cutoff = timezone.now() - timedelta(days=lookback)
        recovered = {}  # real_ip -> set(bogus addresses it was hiding behind)

        for block in bogus_blocks:
            # Correlate on the bogus ip_address that was recorded at block time.
            logs = ActivityLog.objects.filter(
                ip_address=block.ip_address,
                created_at__gte=cutoff,
            ).exclude(detail='').order_by('-created_at')[:500]
            for log in logs:
                real = _real_ip_from_detail(log.detail)
                if real:
                    recovered.setdefault(real, set()).add(block.ip_address)

        self.stdout.write('')
        if recovered:
            self.stdout.write(self.style.WARNING('Recovered real attacker IP(s):'))
            for real_ip, hidden_behind in sorted(recovered.items()):
                behind = ', '.join(sorted(hidden_behind))
                self.stdout.write(f'  {real_ip}   (was hidden behind: {behind})')
        else:
            self.stdout.write('No real IPs recoverable from ActivityLog detail '
                              '(header dumps may be older than the lookback window).')

        # --- 3. Report / apply --------------------------------------------
        self.stdout.write('')
        for b in bogus_blocks:
            self.stdout.write(self.style.NOTICE(f'  delete BlockedIP  {b.ip_address}  ({b.reason})'))
        for r in bogus_rejections[:20]:
            self.stdout.write(self.style.NOTICE(f'  delete NginxRejection  {r.ip_address}  {r.path}'))
        if len(bogus_rejections) > 20:
            self.stdout.write(f'  ... and {len(bogus_rejections) - 20} more NginxRejection rows')

        # Which recovered IPs are actually blockable now?
        to_block = []
        for real_ip in sorted(recovered):
            if WhitelistedIP.is_whitelisted(real_ip):
                self.stdout.write(f'  skip re-block {real_ip} (whitelisted)')
                continue
            if BlockedIP.is_blocked(real_ip):
                self.stdout.write(f'  skip re-block {real_ip} (already blocked)')
                continue
            to_block.append(real_ip)

        if reblock:
            for real_ip in to_block:
                self.stdout.write(self.style.SUCCESS(f'  re-block {real_ip} (recovered real attacker IP)'))

        if not commit:
            self.stdout.write('')
            self.stdout.write(self.style.WARNING('Dry-run only. Re-run with --commit to apply.'))
            return

        # --- Apply ---------------------------------------------------------
        deleted_blocks = 0
        for b in bogus_blocks:
            # Bypass BlockedIP.delete()'s system-EDL guard only where relevant;
            # bogus rows are never the system EDL, so a plain delete is fine.
            BlockedIP.objects.filter(pk=b.pk).delete()
            deleted_blocks += 1

        deleted_rejections, _ = NginxRejection.objects.filter(
            pk__in=[r.pk for r in bogus_rejections]
        ).delete()

        created = 0
        if reblock:
            for real_ip in to_block:
                _, was_created = BlockedIP.objects.get_or_create(
                    ip_address=real_ip,
                    defaults={
                        'reason': 'Re-blocked: recovered real IP after 127.0.0.1 header-spoof cleanup',
                        'auto_blocked': True,
                    },
                )
                if was_created:
                    created += 1

        # Re-sync the Nginx blocklist file / system EDL after mutations.
        try:
            BlockedIP.sync_to_nginx()
            synced = True
        except Exception as e:  # sync must never leave the command half-done silently
            synced = False
            self.stdout.write(self.style.ERROR(f'sync_to_nginx failed: {e}'))

        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS(
            f'Done. Deleted {deleted_blocks} BlockedIP, {deleted_rejections} NginxRejection; '
            f're-blocked {created} real IP(s); nginx sync {"ok" if synced else "FAILED"}.'
        ))
        self.stdout.write('ActivityLog left untouched (immutable audit chain).')
