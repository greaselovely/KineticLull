"""Business logic shared by the `/api/v1/` routes and the legacy shims.

Every function here returns `(payload: dict, status: int, context: dict)`.
`payload` and `status` are the response exactly as the client should see it,
so the v1 route and the frozen legacy path cannot drift. `context` carries
extras the caller wants for the audit log and never reaches the client.

Nothing in this module touches the request object. Authentication, client-IP
resolution, and audit logging stay with the caller, because those differ
between a Ninja operation and a plain Django view.
"""

import os
from datetime import datetime, timezone

from django.conf import settings

from app.models import AppSettings, ExtDynLists, InboxEntry


def strip_scheme(fqdn_list):
    """Drop http:// and https:// prefixes, matching long-standing behavior."""
    return [domain.replace("http://", "").replace("https://", "") for domain in fqdn_list]


def submit_fqdns(user, fqdn_list):
    """Queue a list of FQDNs into the review Inbox.

    Returns (payload, status, context). 201 on success, 400 when the list is
    empty or over `max_fqdns_per_submission`.
    """
    fqdn_list = strip_scheme(fqdn_list or [])

    app_settings = AppSettings.load()
    if not fqdn_list or len(fqdn_list) > app_settings.max_fqdns_per_submission:
        return (
            {'error': f'FQDN list must be 1-{app_settings.max_fqdns_per_submission} entries'},
            400,
            {},
        )

    InboxEntry.objects.create(submitted_by=user, fqdn_list="\r\n".join(fqdn_list))
    return {'message': 'Submission successful'}, 201, {'count': len(fqdn_list)}


def resolve_auto_url(full_auto_url):
    """Accept either a bare auto_url or a full KineticLull URL and return the slug."""
    base_url = getattr(settings, 'KINETICLULL_URL', os.getenv('KINETICLULL_URL', ''))
    if base_url and full_auto_url.startswith(base_url):
        return full_auto_url.replace(base_url, '', 1).lstrip('/')
    return full_auto_url


def update_edl(user, full_auto_url, fqdn_list, command='update'):
    """Append to or replace the contents of an EDL.

    `user` is the authenticated CustomUser; its email local-part is stamped
    into the per-entry comment so an operator can see who added a domain.

    Returns (payload, status, context): 200 on success, 400 for a missing
    auto_url, a bad list size, or an unknown command, 403 for a system EDL,
    404 when the EDL does not exist. On success `context` carries the EDL's
    friendly_name and the submitted count for the audit log.
    """
    current_date_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    attribution = str(user).split("@")[0]

    fqdn_list = strip_scheme(fqdn_list or [])
    auto_url = resolve_auto_url(full_auto_url or '')

    if not auto_url:
        return {'error': 'Missing auto_url'}, 400, {}

    app_settings = AppSettings.load()
    if not fqdn_list or len(fqdn_list) > app_settings.max_fqdns_per_update:
        return (
            {'error': f'FQDN list must be 1-{app_settings.max_fqdns_per_update} entries'},
            400,
            {},
        )

    try:
        edl = ExtDynLists.objects.get(auto_url=auto_url)
    except ExtDynLists.DoesNotExist:
        return {'error': 'EDL not found'}, 404, {}

    if edl.is_system:
        return {'error': 'System EDL is read-only and cannot be modified via API.'}, 403, {}

    if command == 'overwrite':
        # Every provided domain is treated as new.
        edl.ip_fqdn = "\r\n".join(
            f"{domain} # {current_date_time} by {attribution}" for domain in set(fqdn_list)
        )
    elif command == 'update':
        existing_fqdns = edl.ip_fqdn.split("\r\n")
        # Compare on the domain alone; existing entries carry a trailing comment.
        existing_domains = set(
            entry.split(' ')[0] for entry in existing_fqdns if entry.strip()
        )
        new_entries = [
            f"{domain} # {current_date_time} by {attribution}"
            for domain in fqdn_list
            if domain not in existing_domains
        ]
        # Existing entries are preserved verbatim, so no deduplication here.
        edl.ip_fqdn = "\r\n".join(existing_fqdns + new_entries)
    else:
        return {'error': 'Invalid Command'}, 400, {}

    edl.save()
    return (
        {'message': 'Command Successful'},
        200,
        {'friendly_name': edl.friendly_name, 'count': len(fqdn_list), 'command': command},
    )


def block_ip(user, ip, reason):
    """Add an IP to the nginx blocklist.

    Returns (payload, status, context). Refuses whitelisted addresses, since
    silently blocking one would be an ugly way to lock an operator out of
    their own install.
    """
    import ipaddress

    from app.models import BlockedIP, WhitelistedIP

    ip = (ip or '').strip()
    reason = (reason or 'Manually blocked').strip()

    if not ip:
        return {'error': 'IP address required'}, 400, {}

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {'error': 'Invalid IP address'}, 400, {}

    if WhitelistedIP.is_whitelisted(ip):
        return {'error': 'Cannot block a whitelisted IP'}, 400, {}

    _, created = BlockedIP.objects.get_or_create(
        ip_address=ip,
        defaults={'reason': reason, 'blocked_by': user, 'auto_blocked': False},
    )

    if created:
        BlockedIP.sync_to_nginx()

    return {'status': 'blocked', 'created': created, 'ip': ip}, 200, {'created': created, 'reason': reason}


def unblock_ip(ip):
    """Remove an IP from the nginx blocklist."""
    from app.models import BlockedIP

    ip = (ip or '').strip()
    if not ip:
        return {'error': 'IP address required'}, 400, {}

    deleted, _ = BlockedIP.objects.filter(ip_address=ip).delete()
    if deleted:
        BlockedIP.sync_to_nginx()

    return {'status': 'unblocked', 'ip': ip}, 200, {'deleted': bool(deleted)}


def whitelist_ip(user, ip, reason):
    """Whitelist an address or subnet, dropping any matching block."""
    import ipaddress

    from app.models import BlockedIP, WhitelistedIP

    ip = (ip or '').strip()
    reason = (reason or '').strip()

    if not ip:
        return {'error': 'IP address or subnet required'}, 400, {}

    try:
        if '/' in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
    except ValueError:
        return {'error': 'Invalid IP address or subnet'}, 400, {}

    _, created = WhitelistedIP.objects.get_or_create(
        ip_address=ip,
        defaults={'reason': reason, 'added_by': user},
    )

    if not created:
        return {'status': 'already_whitelisted'}, 200, {'created': False}

    blocked = BlockedIP.objects.filter(ip_address=ip)
    if blocked.exists():
        blocked.delete()
        BlockedIP.sync_to_nginx()

    return {'status': 'whitelisted'}, 200, {'created': True, 'reason': reason}


def remove_whitelist_ip(ip):
    """Drop an address or subnet from the whitelist."""
    from app.models import WhitelistedIP

    ip = (ip or '').strip()
    deleted, _ = WhitelistedIP.objects.filter(ip_address=ip).delete()
    if not deleted:
        return {'error': 'Not found'}, 404, {}
    return {'status': 'removed'}, 200, {}


def userid_config(app_settings):
    """Runtime settings the collector extension re-reads on every check-in.

    Serving these from the server is what keeps the extension a thin client:
    changing a heartbeat interval is a settings edit, not a repackage-and-
    redeploy across every managed device.
    """
    return {
        'enabled': app_settings.panos_enabled,
        'heartbeat_seconds': app_settings.userid_heartbeat_seconds,
        'jitter_seconds': app_settings.userid_jitter_seconds,
    }


def record_user_id_checkin(username, ip_address, app_settings,
                           device_id='', agent_version='', chrome_version='',
                           directory_device_id='', device_location=''):
    """Record which user is signed in at an observed address.

    `ip_address` must be the address the server saw on the connection, not
    anything the client sent. That is the whole security model here: a device
    can assert an identity, but only ever for its own traffic.

    Returns (payload, status, context). `context['identity_changed']` marks
    the check-ins worth writing to the audit log; the rest are heartbeats and
    must not be logged (see the note in `app.api.userid`).
    """
    import ipaddress

    from django.utils import timezone

    from app.models import UserIdMapping

    username = (username or '').strip()
    if not username:
        return {'error': 'username required'}, 400, {}

    if not ip_address:
        return {'error': 'Could not determine source address'}, 400, {}

    if app_settings.panos_only_private_ips:
        try:
            parsed = ipaddress.ip_address(ip_address)
        except ValueError:
            return {'error': 'Invalid source address'}, 400, {}
        # A device off-site reports its home NAT address, which would attach a
        # student's name to a public IP shared with strangers.
        if not (parsed.is_private or parsed.is_loopback):
            return {'error': 'Source address is not on an internal network'}, 403, {}

    # Read the incumbent before overwriting it: an address changing hands is
    # the security-relevant event, and update_or_create would erase the
    # evidence of it.
    previous_username = (
        UserIdMapping.objects.filter(ip_address=ip_address)
        .values_list('username', flat=True)
        .first()
    )

    now = timezone.now()
    mapping, created = UserIdMapping.objects.update_or_create(
        ip_address=ip_address,
        defaults={
            'username': username,
            'device_id': device_id or '',
            'directory_device_id': directory_device_id or '',
            'device_location': device_location or '',
            'agent_version': agent_version or '',
            'chrome_version': chrome_version or '',
            'last_checkin': now,
        },
    )

    payload = {'status': 'ok'}
    payload.update(userid_config(app_settings))
    return payload, 200, {
        'created': created,
        'mapping': mapping,
        'previous_username': previous_username,
        'identity_changed': created or previous_username != username,
    }
