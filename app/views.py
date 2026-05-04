from django.views import View
from django.urls import reverse
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.core.paginator import Paginator
from django.http import HttpResponseRedirect
from django.utils.crypto import get_random_string
from django.http import Http404, HttpResponse, JsonResponse
from django.db import models
from django.core.exceptions import PermissionDenied
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.views.decorators.http import require_http_methods
from django.shortcuts import render, redirect, get_object_or_404

import os
import re
import sys
import json
import signal
import hashlib
import secrets
import logging
import ipaddress
import subprocess
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from pathlib import Path

logger = logging.getLogger(__name__)

from users.models import APIKey
# from .models import InboxEntry, ExtDynLists, Script
from .models import InboxEntry, ExtDynLists, Favorite, ActivityLog, AppSettings, BlockedIP, NginxRejection, ShortenedURL, WhitelistedIP, OneTimeFile
from .forms import ExtDynListsForm, ShortenedURLForm
from .email import send_file_shared_email, send_otp_email, send_access_notification

from users.models import CustomUser
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType


def safe_referer_or_index(request):
    """Return the referer URL if it's on the same host, otherwise the index."""
    referer = request.META.get('HTTP_REFERER')
    if referer:
        parsed = urlparse(referer)
        allowed_host = request.get_host().split(':')[0]
        if parsed.hostname == allowed_host:
            return referer
    return reverse('app:index')


class KineticLullLoginView(LoginView):
    """Login view that exposes a warning flag when the client IP is near the failed-login block threshold."""

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        from .models import AppSettings, BlockedIP
        app_settings = AppSettings.load()
        show_warning = False
        if app_settings.failed_login_block_enabled:
            ip = get_client_ip(self.request)
            if ip:
                count = BlockedIP.count_recent_failed_logins(ip)
                if (count >= app_settings.failed_login_warning_threshold
                        and count < app_settings.failed_login_block_threshold):
                    show_warning = True
        context['failed_login_warning'] = show_warning
        return context


def compute_db_checksum():
    """Compute a checksum of critical table row counts and latest IDs."""
    from users.models import CustomUser
    data = '|'.join([
        str(ExtDynLists.objects.count()),
        str(ExtDynLists.objects.order_by('-id').values_list('id', flat=True).first() or 0),
        str(CustomUser.objects.count()),
        str(CustomUser.objects.order_by('-id').values_list('id', flat=True).first() or 0),
        str(ActivityLog.objects.count()),
        str(ActivityLog.objects.order_by('-id').values_list('id', flat=True).first() or 0),
    ])
    return hashlib.sha256(data.encode()).hexdigest()


def check_db_integrity():
    """Compare stored checksum against current state. Returns (checksum_ok, chain_ok, chain_break_id)."""
    import hashlib
    app_settings = AppSettings.load()
    current_checksum = compute_db_checksum()

    checksum_ok = True
    if app_settings.db_checksum and app_settings.db_checksum != current_checksum:
        checksum_ok = False

    chain_ok, chain_break_id = ActivityLog.verify_chain()
    return checksum_ok, chain_ok, chain_break_id


def update_db_checksum():
    """Update the stored checksum to reflect current DB state."""
    app_settings = AppSettings.load()
    app_settings.db_checksum = compute_db_checksum()
    app_settings.save()


def send_syslog(app_settings, user_email, action, target, detail, ip_address):
    """Send a structured syslog message if syslog is enabled."""
    if not app_settings.syslog_enabled or not app_settings.syslog_host:
        return
    try:
        import socket
        hostname = socket.gethostname()
        timestamp = datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')
        body = f'user="{user_email}" action="{action}" target="{target}" detail="{detail}" src={ip_address}'
        # RFC 3164: <priority>TIMESTAMP HOSTNAME APP: MSG (facility local0, severity info = 134)
        syslog_msg = f'<134>{timestamp} {hostname} KineticLull: {body}'
        syslog_msg = syslog_msg[:1024]
        sock_type = socket.SOCK_DGRAM if app_settings.syslog_protocol == 'udp' else socket.SOCK_STREAM
        sock = socket.socket(socket.AF_INET, sock_type)
        sock.settimeout(2)
        if app_settings.syslog_protocol == 'tcp':
            sock.connect((app_settings.syslog_host, app_settings.syslog_port))
            sock.send((syslog_msg + '\n').encode())
        else:
            sock.sendto(syslog_msg.encode(), (app_settings.syslog_host, app_settings.syslog_port))
        sock.close()
    except Exception:
        pass  # Syslog failure should never break the app


def get_client_ip(request):
    """Extract the real client IP, preferring X-Forwarded-For when behind a reverse proxy."""
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('HTTP_X_REAL_IP') or request.META.get('REMOTE_ADDR')


def log_activity(request, action, target='', detail='', user=None):
    """Log a user activity to the database, forward to syslog, purge old logs, and update the integrity checksum."""
    log_user = user or (request.user if request.user.is_authenticated else None)
    ip_address = get_client_ip(request)
    ActivityLog.objects.create(
        user=log_user,
        action=action,
        target=target,
        detail=detail,
        ip_address=ip_address,
    )
    # Forward to syslog
    try:
        app_settings = AppSettings.load()
        user_email = log_user.email if log_user else 'System'
        send_syslog(app_settings, user_email, action, target, detail, ip_address)
    except Exception:
        pass
    # Purge logs older than retention period
    try:
        if not app_settings:
            app_settings = AppSettings.load()
        cutoff = datetime.now(timezone.utc) - timedelta(days=app_settings.log_retention_days)
        ActivityLog.objects.filter(created_at__lt=cutoff).delete()
    except Exception:
        pass
    update_db_checksum()


def get_security_summary(user):
    """Return security summary dict for superusers, or None."""
    if not user.is_superuser:
        return None
    from django.utils import timezone as tz
    twenty_four_hours_ago = tz.now() - timedelta(hours=24)
    return {
        'blocked_ips': BlockedIP.objects.count(),
        'rejections_24h': NginxRejection.objects.filter(timestamp__gte=twenty_four_hours_ago).count(),
        'auto_blocked_24h': BlockedIP.objects.filter(auto_blocked=True, blocked_at__gte=twenty_four_hours_ago).count(),
    }


def get_visible_edls(user):
    """Return EDLs visible to the user based on group membership. Superusers see all."""
    if user.is_superuser:
        return ExtDynLists.objects.all()
    user_groups = user.groups.all()
    return ExtDynLists.objects.filter(
        models.Q(groups__in=user_groups) | models.Q(groups__isnull=True)
    ).distinct()


def get_edl_for_user(user, **kwargs):
    """Get a single EDL if the user has access, or raise 404."""
    edl = get_object_or_404(ExtDynLists, **kwargs)
    if user.is_superuser:
        return edl
    user_groups = user.groups.all()
    if edl.groups.exists() and not edl.groups.filter(id__in=user_groups).exists():
        raise PermissionDenied
    return edl


@login_required
def index_view(request):
    """
    Display the index view with a list of ExtDynLists items.

    This view retrieves all ExtDynLists items and prepares them for display. For each item, 
    it constructs the full URL by appending the 'auto_url' to the base URL. The base URL is 
    obtained from Django settings or environment variables. Additionally, it processes the 
    'ip_fqdn' field to display a limited number of entries with an ellipsis if the count 
    exceeds a certain threshold (e.g., more than 3 entries). The 'ip_fqdn_count' and a flag 
    'display_ellipsis' are set for each item accordingly.

    Parameters:
    request: The HttpRequest object.

    Returns:
    HttpResponse: Renders the 'index.html' template with the context containing the list of 
                ExtDynLists items and their processed data.
    """

    app_settings = AppSettings.load()
    items = get_visible_edls(request.user)
    default_per_page = str(app_settings.default_edl_per_page)
    per_page = request.GET.get("per_page", default_per_page)
    try:
        per_page = max(1, min(int(per_page), 100))
    except (ValueError, TypeError):
        per_page = app_settings.default_edl_per_page
    paginator = Paginator(items, per_page)
    preview = app_settings.edl_preview_entries
    base_url = settings.KINETICLULL_URL if hasattr(settings, 'KINETICLULL_URL') else os.environ.get('KINETICLULL_URL', 'http://127.0.0.1:8000')
    for item in items:
        item.full_url = base_url + ('/' if item.auto_url[0] != '/' else '') + item.auto_url
        item.ip_fqdn = item.ip_fqdn.split('\r\n')
        item.ip_fqdn_count = len(item.ip_fqdn)
        item.display_ellipsis = item.ip_fqdn_count > preview
        item.ip_fqdn = item.ip_fqdn[:preview]
    favorite_ids = set(Favorite.objects.filter(user=request.user).values_list('edl_id', flat=True))

    # Check which EDLs are actively polled (delete-protected)
    protected_edls = set()
    if app_settings.edl_delete_protection:
        from django.utils import timezone as tz
        from datetime import timedelta
        window_start = tz.now() - timedelta(minutes=app_settings.edl_delete_window_minutes)
        from django.db.models import Count
        active_edls = (
            ActivityLog.objects.filter(action='edl_access', created_at__gte=window_start)
            .values('target')
            .annotate(count=Count('id'))
            .filter(count__gte=app_settings.edl_delete_threshold)
            .values_list('target', flat=True)
        )
        protected_edls = set(active_edls)

    for item in items:
        item.is_favorited = item.id in favorite_ids
        item.is_protected = item.friendly_name in protected_edls

    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    context = {'items': items, 'page_obj': page_obj, 'per_page': per_page}

    # Security summary for superusers
    summary = get_security_summary(request.user)
    if summary:
        context['security_summary'] = summary

    return render(request, 'index.html', context)

@login_required
def item_detail_view(request, item_id: int):
    """
    Retrieves and displays details for a specific External Dynamic List (EDL) item identified by its item_id.
    
    This view fetches an EDL instance from the database using the provided item_id. If the item exists, its 'ip_fqdn'
    field, which is a string containing network addresses separated by carriage returns and new lines, is split into a
    list for easier display. The item details, including its friendly name, are then passed to the template for rendering.

    Parameters:
    - request: HttpRequest object representing the current request.
    - item_id: The ID of the EDL item whose details are to be displayed.

    Returns:
    - HttpResponse object with the rendered page displaying the details of the specified EDL item.
    """
    item = get_edl_for_user(request.user, id=item_id)
    item.ip_fqdn = item.ip_fqdn.split('\r\n')
    context = {'item': item, 'friendly_name': item.friendly_name }
    return render(request, 'item_detail.html', context)

def show_ip_fqdn(request, auto_url):
    """
    Display the IP/FQDN for a given ExtDynLists item based on its auto URL.

    This view retrieves an ExtDynLists item using the provided auto URL. If the item is found,
    it checks if the user's IP address is allowed access based on the ACL list of the item.
    If the IP address is allowed (either explicitly or via a wildcard '*'), the 'ip_fqdn' field 
    of the item is returned as a plain text response. If the IP address is not allowed, a 
    PermissionDenied exception is raised.

    Parameters:
    request: The HttpRequest object.
    auto_url (str): The auto-generated URL identifier for the ExtDynLists item.

    Returns:
    HttpResponse: A HttpResponse object with 'text/plain' content type, containing the
                'ip_fqdn' data if access is allowed.
    Raises:
    PermissionDenied: If the user's IP address is not allowed access as per the ACL list.
    """

    user_ip = get_client_ip(request)
    http_headers = {k.replace('HTTP_', '').lower(): v for k, v in request.META.items() if k.startswith('HTTP_')}
    detail = '; '.join(f'{k}={v}' for k, v in http_headers.items()) or 'No headers'

    try:
        edl = ExtDynLists.objects.get(auto_url=auto_url)
    except ExtDynLists.DoesNotExist:
        log_activity(request, 'edl_not_found', auto_url, detail)
        if not BlockedIP.check_scanner_pattern_block(user_ip, request.path):
            BlockedIP.check_autoblock(user_ip)
        request._kl_logged_404 = True
        raise Http404

    acl_list = edl.acl.split('\n')
    if '*' in acl_list or check_acl(user_ip, acl_list):
        log_activity(request, 'edl_access', edl.friendly_name, detail)
        return HttpResponse(edl.ip_fqdn, content_type="text/plain")
    else:
        log_activity(request, 'edl_denied', edl.friendly_name, detail)
        raise PermissionDenied


def robots_txt_view(request):
    body = AppSettings.load().robots_txt or ''
    return HttpResponse(body, content_type='text/plain; charset=utf-8')


def custom_404(request, exception):
    path = request.get_full_path()
    if not getattr(request, '_kl_logged_404', False):
        user_agent = request.META.get('HTTP_USER_AGENT', '') or 'No User-Agent'
        log_activity(request, 'not_found', path, f'Agent: {user_agent}')
        ip = get_client_ip(request)
        if ip:
            if not BlockedIP.check_scanner_pattern_block(ip, request.path):
                BlockedIP.check_autoblock(ip)
    return render(request, '404.html', {'request_path': path}, status=404)


@login_required
def create_new_edl(request):
    """
    Handles the creation of a new External Dynamic List (EDL) entry through a form. If the request is POST and the form is valid,
    a new EDL instance is created, populated with the form data, and saved to the database with additional processing for the 'acl'
    field. If the request is GET, an empty form is presented to the user.

    Upon a successful POST request, the 'acl' field is processed to filter out blank lines and correct each network address
    before saving. The function redirects to the home page after successful EDL creation or re-renders the form with errors
    on validation failure.

    Parameters:
    - request: HttpRequest object representing the current request.

    Returns:
    - HttpResponse object with the rendered form for creating a new EDL on GET requests, or a redirect to the home page
      after successfully creating an EDL on POST requests. In case of form validation failure, re-renders the form with errors.
    """
    if request.method == 'POST':
        form = ExtDynListsForm(request.POST)
        if form.is_valid():
            edl_instance = form.save(commit=False)

            # Process each line in acl, filtering out only blank lines
            acl_lines = (line.strip() for line in edl_instance.acl.splitlines())
            corrected_acl = [get_corrected_network_address(line) for line in acl_lines if line]
            
            edl_instance.ip_fqdn = "\r\n".join([fqdn.replace("http://", "").replace("https://", "") for fqdn in edl_instance.ip_fqdn.split('\r\n')])
            edl_instance.acl = "\n".join(corrected_acl)
            edl_instance.save()
            edl_instance.groups.set(request.user.groups.all())
            log_activity(request, 'create_edl', edl_instance.friendly_name)
            update_db_checksum()
            return redirect('app:index')
        else:
            logger.warning("EDL creation form errors: %s", form.errors)
    else:
        form = ExtDynListsForm(initial={'acl': '*', })

    return render(request, 'edit_edl.html', {'form': form})

@login_required
def edit_ext_dyn_list_view(request, id=None):
    """
    Edit an existing ExtDynLists item.

    This view handles the editing of an ExtDynLists item. It first tries to retrieve the item 
    using the provided ID. If the item is found and the request is a POST, the form is 
    processed. Valid form submissions apply corrections to the 'acl' field, such as formatting 
    network addresses and removing blank lines. The corrected 'acl' is then saved. If the 
    form is invalid, or if the request is not a POST, the form is displayed for editing, 
    pre-populated with the item's current data. If no ID is provided, the function allows 
    creating a new item.

    Parameters:
    request: The HttpRequest object.
    id (int, optional): The unique identifier of the item to be edited. If None, a new item 
                        creation form is displayed.

    Returns:
    HttpResponse: Redirects to the home page on successful edit or creation. Otherwise, 
                renders the 'edit_edl.html' template with the form.
    """
    if id:
        edl = get_edl_for_user(request.user, id=id)
        # Snapshot before values for diff
        before = {
            'friendly_name': edl.friendly_name,
            'ip_fqdn': set(e.strip() for e in edl.ip_fqdn.split('\r\n') if e.strip()),
            'acl': set(e.strip() for e in edl.acl.split('\n') if e.strip()),
            'policy_reference': edl.policy_reference,
        }
        if request.method == 'POST':
            form = ExtDynListsForm(request.POST, instance=edl)
            if form.is_valid():
                # Apply corrections to the acl field
                edl_instance = form.save(commit=False)

                # Process each line in acl, filtering out only blank lines
                acl_lines = (line.strip() for line in edl_instance.acl.splitlines())
                corrected_acl = [get_corrected_network_address(line) for line in acl_lines if line]
                edl_instance.ip_fqdn = "\r\n".join([fqdn.replace("http://", "").replace("https://", "") for fqdn in edl_instance.ip_fqdn.split('\r\n')])
                edl_instance.acl = "\n".join(corrected_acl)
                edl_instance.save()

                # Build detailed change log
                changes = []
                if edl_instance.friendly_name != before['friendly_name']:
                    changes.append(f'Renamed: {before["friendly_name"]} -> {edl_instance.friendly_name}')
                after_fqdns = set(e.strip() for e in edl_instance.ip_fqdn.split('\r\n') if e.strip())
                added_fqdns = after_fqdns - before['ip_fqdn']
                removed_fqdns = before['ip_fqdn'] - after_fqdns
                if added_fqdns:
                    changes.append(f'Added entries: {", ".join(sorted(added_fqdns))}')
                if removed_fqdns:
                    changes.append(f'Removed entries: {", ".join(sorted(removed_fqdns))}')
                after_acl = set(e.strip() for e in edl_instance.acl.split('\n') if e.strip())
                added_acl = after_acl - before['acl']
                removed_acl = before['acl'] - after_acl
                if added_acl:
                    changes.append(f'Added ACL: {", ".join(sorted(added_acl))}')
                if removed_acl:
                    changes.append(f'Removed ACL: {", ".join(sorted(removed_acl))}')
                if edl_instance.policy_reference != before['policy_reference']:
                    changes.append('Updated notes')
                detail = '; '.join(changes) if changes else 'No changes'
                log_activity(request, 'edit_edl', edl_instance.friendly_name, detail)
                update_db_checksum()
                return redirect('app:index')
        else:
            form = ExtDynListsForm(instance=edl)
    else:
        if request.method == 'POST':
            form = ExtDynListsForm(request.POST)
            if form.is_valid():
                form.save()
                return redirect(safe_referer_or_index(request))
        else:
            form = ExtDynListsForm()

    template_name = "edit_edl.html"
    context = {"form": form}
    return render(request, template_name=template_name, context=context)

@login_required
def clone_ext_dyn_list_view(request, item_id):
    """
    Create a clone of an existing ExtDynLists item.

    This view handles the cloning of an ExtDynLists item. It first retrieves the original item 
    using its ID. If the item is found and a POST request is made with valid form data, 
    a new ExtDynLists item is created with data from the form, except for the ID and auto_url, 
    which are set to None and a new hash, respectively. The cloned item is then saved to the 
    database. If the request is not POST or the form data is invalid, the form is displayed 
    initially populated with data from the original item, with '-Copy' appended to the 
    'friendly_name'.

    Parameters:
    request: The HttpRequest object.
    item_id (int): The unique identifier of the item to be cloned.

    Returns:
    HttpResponse: If POST and form is valid, redirects to the home page. Otherwise, renders 
                the 'edit_edl.html' template with the form.
    """

    original_item = get_edl_for_user(request.user, id=item_id)

    if request.method == 'POST':
        form = ExtDynListsForm(request.POST)
        if form.is_valid():
            cloned_item = ExtDynLists(**form.cleaned_data)
            cloned_item.id = None
            cloned_item.auto_url = ''
            cloned_item.save()
            cloned_item.groups.set(request.user.groups.all())
            log_activity(request, 'clone_edl', cloned_item.friendly_name, f'Cloned from {original_item.friendly_name}')
            update_db_checksum()
            return redirect(safe_referer_or_index(request))
        else:
            logger.warning("EDL clone form errors: %s", form.errors)
    else:
        date_time_format = "%m/%d/%Y @ %H:%M:%S UTC"
        now = datetime.now().strftime(date_time_format)
        initial_data = {
            'friendly_name': original_item.friendly_name + " Clone",
            'ip_fqdn' : original_item.ip_fqdn,
            'acl' : original_item.acl,
            'policy_reference' : f'Cloned from "{original_item.friendly_name}" on {now}:\n{original_item.policy_reference}',
        }
        form = ExtDynListsForm(initial=initial_data)
    
    return render(request, 'edit_edl.html', {'form': form})

@login_required
def download_ip_fqdn(request, item_id):
    """
    Generate and return a text file download of the IP/FQDN data for a specific item.

    This function retrieves an item from the ExtDynLists model using its ID. If the item
    is found, it prepares a response with the 'ip_fqdn' field of the item as a text file
    download. If the item is not found, a 404 error is raised. The response sets the
    'Content-Disposition' header to prompt a file download with a filename based on the
    item's friendly name.

    Parameters:
    request: The HttpRequest object.
    item_id (int): The unique identifier of the item whose IP/FQDN data is to be downloaded.

    Returns:
    HttpResponse: A HttpResponse object with 'text/plain' content type, containing the
                'ip_fqdn' data and set up to prompt a file download.
    """

    item = get_edl_for_user(request.user, id=item_id)
    text_content = item.ip_fqdn
    response = HttpResponse(text_content, content_type='text/plain')
    safe_name = re.sub(r'[^\w\s\-.]', '', item.friendly_name).strip() or 'download'
    response['Content-Disposition'] = f'attachment; filename="{safe_name}.txt"'
    return response

@login_required
def delete_item(request, item_id):
    """
    Delete a specific item from the database based on its ID and redirects back to the original page.

    This function retrieves an item using its unique ID from the ExtDynLists model.
    If the item exists, it is deleted. Otherwise, a 404 error is raised. After
    deletion, the function attempts to redirect back to the original page using the
    'HTTP_REFERER' header from the request. If this header is not available, it redirects
    to a fallback URL (e.g., the home page).

    Parameters:
    - request: HttpRequest object representing the current request.
    - item_id (int): The unique identifier of the item to be deleted.

    Returns:
    - HttpResponseRedirect: Redirects to the referring page or to a fallback URL after the item is deleted.
    """
    item = get_edl_for_user(request.user, id=item_id)

    # Check if EDL is actively being polled
    app_settings = AppSettings.load()
    if app_settings.edl_delete_protection:
        from django.utils import timezone as tz
        from datetime import timedelta

        # Check for force delete (superuser override with name confirmation)
        force = False
        try:
            body = json.loads(request.body)
            force = body.get('force', False)
        except (json.JSONDecodeError, ValueError):
            pass

        window_start = tz.now() - timedelta(minutes=app_settings.edl_delete_window_minutes)
        access_count = ActivityLog.objects.filter(
            action='edl_access',
            target=item.friendly_name,
            created_at__gte=window_start,
        ).count()
        if access_count >= app_settings.edl_delete_threshold and not (force and request.user.is_superuser):
            return JsonResponse({
                'protected': True,
                'edl_name': item.friendly_name,
                'access_count': access_count,
                'window_minutes': app_settings.edl_delete_window_minutes,
            }, status=409)

    log_activity(request, 'delete_edl', item.friendly_name)
    item.delete()
    update_db_checksum()

    # Redirect back to the referring page if it's on the same host
    referer_url = request.META.get('HTTP_REFERER')
    if referer_url:
        parsed = urlparse(referer_url)
        allowed_host = request.get_host().split(':')[0]
        if parsed.hostname == allowed_host:
            return HttpResponseRedirect(referer_url)
    return redirect(reverse('app:index'))

def check_acl(ip, networks: list):
    """
    Check if a given IP address is part of any of the specified networks.

    This function iterates through a list of network strings and determines 
    whether the given IP address is part of these networks. The function 
    supports both CIDR notations and single IP addresses. Single IP addresses 
    are treated as individual networks (with a /32 subnet mask). Commented 
    lines (starting with '#') in the network list are ignored.

    Parameters:
    ip (str): The IP address to check.
    networks (list of str): A list of network strings in CIDR notation or 
                            single IP addresses. Commented lines are allowed.

    Returns:
    bool: True if the IP address is within any of the specified networks, 
        False otherwise.
    """
    ip_addr = ipaddress.ip_address(ip)
    for network_str in networks:
        if network_str.startswith('#') or network_str.startswith('*'):
            continue  # Ignore comment lines

        # Add '/32' to single IP addresses to treat them as individual networks
        if '/' not in network_str:
            network_str += '/32'

        network = ipaddress.ip_network(network_str, strict=False)
        if ip_addr in network:
            return True
    return False

def get_corrected_network_address(value):
    """
    Corrects the given network address string to a valid format or marks it as an invalid entry.

    This function takes a network address string and attempts to validate it. If the input 
    is a valid single IP address or a valid CIDR notation, it returns the value as-is. 
    If the input is an invalid network address, it converts the string into a comment 
    indicating that it's an invalid entry. The function also handles and preserves existing 
    comments (lines starting with '#') and empty strings without modification.

    Parameters:
    value (str): The network address string to be validated and corrected.

    Returns:
    str: The original valid network address or single IP, a commented string indicating an 
         invalid entry, or the original comment/empty string.
    """
    original_value = value.strip()  # Remove leading/trailing whitespace
    if not original_value or original_value.startswith('#') or original_value == '*':  # Skip empty strings and existing comments
        return original_value  # Return as-is if it's already a comment or empty
    try:
        # Check if it's a single IP or a network
        if '/' in original_value:
            network = ipaddress.ip_network(original_value, strict=False)
            return str(network)
        else:
            ipaddress.ip_address(original_value)
            return original_value
    except ValueError:
        # Invalid IP address or network, turn it into a comment with an explanation
        return f"# Invalid entry: {original_value}"

def generate_api_key(user):
    """
    Generates a new API key for a given user. If an API key already exists for the user, it updates the existing key.

    This function uses `secrets.token_urlsafe()` to generate a secure, random API key. It ensures that each user has only
    one API key by checking for an existing key and updating it if found. If no key exists, it creates a new APIKey instance.

    Parameters:
    - user: User instance for whom the API key is being generated or updated.

    Returns:
    - A tuple containing the new API key string and a boolean indicating whether the API key was created (True) or updated (False).
    """
    app_settings = AppSettings.load()
    api_key, created = APIKey.objects.get_or_create(user=user)
    new_key = secrets.token_urlsafe(50)
    api_key.key = new_key
    api_key.expires_at = datetime.now(timezone.utc) + timedelta(days=app_settings.api_key_expiration_days)
    api_key.save()
    return new_key, created

def validate_api_key(key: str) -> bool:
    """
    Validates an API key by checking if it exists in the database.

    This function queries the database to see if the provided API key exists within the APIKey model. It's used
    to verify that an API key is valid and has been issued, as part of authentication or permission checks in
    API or system operations that require key-based access control.

    Parameters:
    - key: A string representing the API key to be validated.

    Returns:
    - A boolean value: True if the API key exists in the database, False otherwise.
    """
    return APIKey.objects.filter(key=key).exists()

def authenticate_user(api_key_header):
    """
    Authenticates a user based on an API key provided in the header.

    This function expects the `api_key_header` to be in the format "Bearer YOUR_API_KEY_HERE". It attempts to
    extract the API key from the header and then checks if this key corresponds to an existing APIKey instance
    in the database. If a matching APIKey instance is found, the associated user is returned, otherwise, None
    is returned, indicating that authentication has failed.

    Parameters:
    - api_key_header: The API key header string, expected to start with "Bearer " followed by the API key.

    Returns:
    - The user associated with the provided API key if authentication is successful; otherwise, None.
    """
    try:
        _, api_key = api_key_header.split()  # This unpacks the header into two parts: "Bearer" and the actual key
    except ValueError:
        # If split() fails or doesn't produce exactly two items, then we have only received the key already and just assign it for user lookup.
        api_key = api_key_header

    try:
        api_key_instance = APIKey.objects.get(key=api_key)
        if api_key_instance.is_expired:
            return None
        return api_key_instance.user
    except APIKey.DoesNotExist:
        return None

def logout_view(request):
    """
    Logs out the user and redirects them to the homepage.

    This view handles the process of logging out a user by deleting the sessionid and csrftoken cookies,
    effectively invalidating the user's session. It then calls Django's logout function to officially
    log the user out before redirecting the user to the homepage.

    Parameters:
    - request: HttpRequest object representing the current request.

    Returns:
    - An HttpResponseRedirect to the homepage, with session and CSRF cookies removed.
    """
    response = redirect('/')
    response.delete_cookie('sessionid')
    response.delete_cookie('csrftoken')
    logout(request)
    return response

@method_decorator(csrf_exempt, name='dispatch')
class SubmitFQDNView(View):
    """
    A class-based view that handles the submission of FQDN (Fully Qualified Domain Names) lists via a POST request.
    It authenticates the user using an API key provided in the 'Authorization' header, validates the FQDN list,
    and then stores it in the database associated with the user's email.

    The view is CSRF exempt to facilitate API access. It ensures that the FQDN list is not empty, does not exceed
    50 entries, and sanitizes the list by removing any protocol prefixes before storing.

    Methods:
    - post: Handles POST requests, expecting a JSON body with a 'fqdn_list' key mapping to a list of FQDN strings.
    
    Returns:
    - JsonResponse indicating success with HTTP 201 status code, or an error with appropriate HTTP status codes
      (401 for invalid API key, 400 for invalid FQDN list, etc.) and error messages.
    """
    def post(self, request, *args, **kwargs):
        api_key = request.headers.get('Authorization')
        user = authenticate_user(api_key)
        
        if user is None:
            return JsonResponse({'error': 'Invalid API key'}, status=401)
        
        data = json.loads(request.body)
        fqdn_list = data.get('fqdn_list', [])
        fqdn_list = [domain.replace("http://", "").replace("https://", "") for domain in fqdn_list]

        app_settings = AppSettings.load()
        if not fqdn_list or len(fqdn_list) > app_settings.max_fqdns_per_submission:
            return JsonResponse({'error': f'FQDN list must be 1-{app_settings.max_fqdns_per_submission} entries'}, status=400)

        InboxEntry.objects.create(submitted_by=user, fqdn_list="\r\n".join(fqdn_list))
        log_activity(request, 'api_submit', f'{len(fqdn_list)} FQDNs', user=user)
        return JsonResponse({'message': 'Submission successful'}, status=201)

@csrf_exempt
@require_http_methods(["POST"])
def update_edl_fqdn(request):
    """
    Updates an External Dynamic List (EDL) with new Fully Qualified Domain Names (FQDNs) based on the provided command.
    It supports adding new FQDNs or overwriting the existing list with a new set of FQDNs. The function performs
    user authentication using an API key, validates the request data, and applies the specified changes to the EDL.

    The request must include 'auto_url' to identify the EDL, 'fqdn_list' containing the domains to add or overwrite,
    and 'command' indicating the update operation mode ('update' or 'overwrite'). FQDNs are cleansed of protocols
    (http://, https://) before processing.

    Parameters:
    - request: HttpRequest object containing metadata about the request including 'Authorization' header with the API key,
               and a JSON body with 'auto_url', 'fqdn_list', and 'command'.

    Returns:
    - JsonResponse indicating the outcome of the operation. Returns HTTP 201 with a success message if the update
      is successful, HTTP 401 for unauthorized requests, HTTP 400 for requests with missing or invalid data,
      or HTTP 500 for server errors.
    """
    try:
        current_date_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        data = json.loads(request.body)
        auth_header = request.headers.get('Authorization')
        api_key = auth_header.split(' ')[-1] if auth_header else None
        user = authenticate_user(api_key)
        user = str(user)
        user, _ = user.split("@")

        if user is None:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # Extract the auto_url from the request data
        full_auto_url = data.get('auto_url', '')
        fqdn_list = data.get('fqdn_list', [])
        fqdn_list = [domain.replace("http://", "").replace("https://", "") for domain in fqdn_list]
        command = data.get('command', 'update')  # Default to 'update'

        # Obtain the base URL from settings or .env
        base_url = getattr(settings, 'KINETICLULL_URL', os.getenv('KINETICLULL_URL', ''))

        # Remove the base URL part from the full_auto_url
        if base_url and full_auto_url.startswith(base_url):
            auto_url = full_auto_url.replace(base_url, '', 1).lstrip('/')
        else:
            auto_url = full_auto_url

        if not auto_url:
            return JsonResponse({'error': 'Missing auto_url'}, status=400)

        app_settings = AppSettings.load()
        if not fqdn_list or len(fqdn_list) > app_settings.max_fqdns_per_update:
            return JsonResponse({'error': f'FQDN list must be 1-{app_settings.max_fqdns_per_update} entries'}, status=400)

        try:
            edl = ExtDynLists.objects.get(auto_url=auto_url)
        except ExtDynLists.DoesNotExist:
            return JsonResponse({'error': 'EDL not found'}, status=404)

        if command == 'overwrite':
            # For 'overwrite', treat all provided domains as new
            edl.ip_fqdn = "\r\n".join([f"{domain} # {current_date_time} by {user}" for domain in set(fqdn_list)])
        elif command == 'update':
            existing_fqdns = edl.ip_fqdn.split("\r\n")
            
            # Extract just the domain names from existing entries to identify new domains
            existing_domains = set(entry.split(' ')[0] for entry in existing_fqdns if entry.strip())
            
            # Determine which domains from the provided list are new
            new_domains = [domain for domain in fqdn_list if domain not in existing_domains]
            
            # Append additional info only to new domains
            new_fqdn_entries = [f"{domain} # {current_date_time} by {user}" for domain in new_domains]
            
            # Combine new entries with existing ones, no need to deduplicate here as existing entries are preserved as is
            updated_fqdns = existing_fqdns + new_fqdn_entries
            edl.ip_fqdn = "\r\n".join(updated_fqdns)
        
        else:
            return JsonResponse({'error': 'Invalid Command'}, status=400)

        edl.save()
        log_activity(request, f'api_{command}', edl.friendly_name, f'{len(fqdn_list)} FQDNs')
        return JsonResponse({'message': 'Command Successful'}, status=200)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': 'An error occurred'}, status=500)

@login_required
def review_submission(request, submission_id: int):
    """
    Presents a form for reviewing and processing a submission entry. Upon a POST request, if the form is valid,
    a new External Dynamic List (EDL) is created using the data from the submission, and the submission is then deleted.

    The function handles both GET and POST requests. For GET requests, it pre-populates a form with information
    from the submission, including a policy reference constructed from the submission's timestamp and user email.
    For POST requests, it processes the form data, creates a new EDL entry, deletes the processed submission,
    and redirects to the submission list view.

    Parameters:
    - request: HttpRequest object representing the current request.
    - submission_id: The ID of the submission entry to review and process.

    Returns:
    - HttpResponse object with the rendered review page on GET requests or a redirect on successful form processing.
    """
    date_time_format = "%m/%d/%Y @ %H:%M:%S UTC"
    submission = get_object_or_404(InboxEntry, id=submission_id)

    if request.method == 'POST':
        form = ExtDynListsForm(request.POST)
        if form.is_valid():
            new_edl = form.save(commit=False)
            new_edl.fqdn_list = submission.fqdn_list
            new_edl.save()
            new_edl.groups.set(request.user.groups.all())
            submission.delete()
            return redirect('app:submission_list')
    else:
        submitted_at_str = submission.submitted_at.strftime(date_time_format) if submission.submitted_at else "N/A"
        submitter_email = submission.submitted_by.email if submission.submitted_by else "Unknown"
        summary_policy_reference = f"Submitted via API on {submitted_at_str} by {submitter_email}"
        form = ExtDynListsForm(initial={
            'ip_fqdn': submission.fqdn_list,
            'acl' : '*',
            'policy_reference': summary_policy_reference,
        })
    
    return render(request, 'review_submission.html', {
        'form': form,
        'submission': submission,
    })

@login_required
def delete_submission(request, submission_id: int):
    """
    Deletes a specified submission entry and redirects to the submission list view.

    This view retrieves an InboxEntry object by its `submission_id` and deletes it from the database.
    After deletion, the user is redirected to the list of submissions, typically to update the UI and
    show the list without the deleted entry.

    Parameters:
    - request: HttpRequest object representing the current request.
    - submission_id: The ID of the submission entry to be deleted.

    Returns:
    - An HttpResponseRedirect to the submission list view after the deletion.
    """
    submission = get_object_or_404(InboxEntry, id=submission_id)
    submission.delete()
    return redirect('app:submission_list')

@login_required
def submission_list(request):
    """
    Retrieves and displays a list of all submission entries.

    This view fetches all instances of InboxEntry from the database, splits the 'fqdn_list' field of each
    submission into a list of FQDNs (for display purposes), and passes the submissions to the template for rendering.
    It's designed to provide an overview of all submissions, allowing users to review, edit, or delete them as needed.

    Parameters:
    - request: HttpRequest object representing the current request.

    Returns:
    - HttpResponse object with the rendered page displaying the list of submissions.
    """
    app_settings = AppSettings.load()
    submissions = InboxEntry.objects.all()
    default_per_page = str(app_settings.default_edl_per_page)
    per_page = request.GET.get("per_page", default_per_page)
    try:
        per_page = max(1, min(int(per_page), 100))
    except (ValueError, TypeError):
        per_page = app_settings.default_edl_per_page
    paginator = Paginator(submissions, per_page)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    preview = app_settings.edl_preview_entries
    for submission in page_obj:
        fqdn_items = submission.fqdn_list.split('\r\n')
        submission.fqdn_display = fqdn_items[:preview]
        submission.fqdn_count = len(fqdn_items)
        submission.display_ellipsis = submission.fqdn_count > preview
    return render(request, 'submission_list.html', {
        'page_obj': page_obj,
        'per_page': per_page,
    })

@login_required
@require_http_methods(["POST"])
def toggle_favorite(request, item_id):
    edl = get_edl_for_user(request.user, id=item_id)
    favorite, created = Favorite.objects.get_or_create(user=request.user, edl=edl)
    if not created:
        favorite.delete()
    return JsonResponse({'favorited': created})


@login_required
def favorites_view(request):
    app_settings = AppSettings.load()
    favorite_edl_ids = Favorite.objects.filter(user=request.user).values_list('edl_id', flat=True)
    items = get_visible_edls(request.user).filter(id__in=favorite_edl_ids)
    default_per_page = str(app_settings.default_edl_per_page)
    per_page = request.GET.get("per_page", default_per_page)
    try:
        per_page = max(1, min(int(per_page), 100))
    except (ValueError, TypeError):
        per_page = app_settings.default_edl_per_page
    paginator = Paginator(items, per_page)
    preview = app_settings.edl_preview_entries
    base_url = settings.KINETICLULL_URL if hasattr(settings, 'KINETICLULL_URL') else os.environ.get('KINETICLULL_URL', 'http://127.0.0.1:8000')
    for item in items:
        item.full_url = base_url + ('/' if item.auto_url[0] != '/' else '') + item.auto_url
        item.ip_fqdn = item.ip_fqdn.split('\r\n')
        item.ip_fqdn_count = len(item.ip_fqdn)
        item.display_ellipsis = item.ip_fqdn_count > preview
        item.ip_fqdn = item.ip_fqdn[:preview]
        item.is_favorited = True

    # Check which EDLs are actively polled (delete-protected)
    protected_edls = set()
    if app_settings.edl_delete_protection:
        from django.utils import timezone as tz
        from datetime import timedelta
        from django.db.models import Count
        window_start = tz.now() - timedelta(minutes=app_settings.edl_delete_window_minutes)
        active_edls = (
            ActivityLog.objects.filter(action='edl_access', created_at__gte=window_start)
            .values('target')
            .annotate(count=Count('id'))
            .filter(count__gte=app_settings.edl_delete_threshold)
            .values_list('target', flat=True)
        )
        protected_edls = set(active_edls)

    for item in items:
        item.is_protected = item.friendly_name in protected_edls

    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    context = {'items': items, 'page_obj': page_obj, 'per_page': per_page, 'favorites_view': True}
    summary = get_security_summary(request.user)
    if summary:
        context['security_summary'] = summary
    return render(request, 'index.html', context)


@login_required
def activity_log_view(request):
    if not (request.user.is_superuser or request.user.has_perm('app.view_activitylog')):
        raise PermissionDenied
    app_settings = AppSettings.load()
    logs = ActivityLog.objects.all()
    search = request.GET.get("q", "").strip()
    if search:
        logs = logs.filter(
            models.Q(action__icontains=search) |
            models.Q(target__icontains=search) |
            models.Q(detail__icontains=search) |
            models.Q(ip_address__icontains=search) |
            models.Q(user__email__icontains=search)
        )
    default_per_page = str(app_settings.default_log_per_page)
    per_page = request.GET.get("per_page", default_per_page)
    try:
        per_page = max(1, min(int(per_page), 100))
    except (ValueError, TypeError):
        per_page = app_settings.default_log_per_page
    paginator = Paginator(logs, per_page)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    return render(request, 'activity_log.html', {
        'page_obj': page_obj,
        'per_page': per_page,
        'search': search,
    })


@login_required
def integrity_check_view(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    checksum_ok, chain_ok, chain_break_id = check_db_integrity()

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'reset_checksum':
            update_db_checksum()
            log_activity(request, 'reset_checksum', 'DB checksum reset by admin')
            messages.success(request, 'Checksum reset to current state.')
            return redirect('app:integrity_check')
        elif action == 'rebase_chain':
            ActivityLog.rebase_chain()
            update_db_checksum()
            log_activity(request, 'rebase_chain', 'Log chain rebased by admin')
            messages.success(request, 'Log chain rebased and checksum updated.')
            return redirect('app:integrity_check')

    return render(request, 'integrity_check.html', {
        'checksum_ok': checksum_ok,
        'chain_ok': chain_ok,
        'chain_break_id': chain_break_id,
    })


@login_required
def activity_log_export(request):
    import csv
    import zoneinfo
    from django.utils.dateformat import format as date_format
    if not (request.user.is_superuser or request.user.has_perm('app.view_activitylog')):
        raise PermissionDenied
    logs = ActivityLog.objects.all()
    search = request.GET.get("q", "").strip()
    if search:
        logs = logs.filter(
            models.Q(action__icontains=search) |
            models.Q(target__icontains=search) |
            models.Q(detail__icontains=search) |
            models.Q(ip_address__icontains=search) |
            models.Q(user__email__icontains=search)
        )
    app_settings = AppSettings.load()
    tz = zoneinfo.ZoneInfo(app_settings.timezone)
    ts_format = app_settings.timestamp_format

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="activity_log.csv"'
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'User', 'Action', 'Target', 'Detail', 'IP Address'])
    for log in logs:
        local_time = log.created_at.astimezone(tz)
        writer.writerow([
            date_format(local_time, ts_format),
            log.user.email if log.user else 'System',
            log.action,
            log.target,
            log.detail,
            log.ip_address or '',
        ])
    return response


@login_required
def app_settings_view(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    import zoneinfo
    app_settings = AppSettings.load()
    available_timezones = sorted(zoneinfo.available_timezones())

    valid_ts_formats = [c[0] for c in AppSettings.TIMESTAMP_CHOICES]

    # Field definitions: (POST name, attr name, type, min, max, default)
    int_fields = [
        ('default_edl_per_page', 'default_edl_per_page', 5, 50, 10),
        ('default_log_per_page', 'default_log_per_page', 5, 100, 25),
        ('edl_preview_entries', 'edl_preview_entries', 1, 10, 3),
        ('max_fqdns_per_submission', 'max_fqdns_per_submission', 1, 500, 50),
        ('max_fqdns_per_update', 'max_fqdns_per_update', 1, 500, 50),
        ('max_edls_per_group', 'max_edls_per_group', 1, 500, 25),
        ('max_entries_per_edl', 'max_entries_per_edl', 100, 150000, 5000),
        ('max_inbox_per_user', 'max_inbox_per_user', 5, 100, 25),
        ('log_retention_days', 'log_retention_days', 1, 180, 90),
        ('session_timeout_minutes', 'session_timeout_minutes', 5, 480, 30),
        ('api_key_expiration_days', 'api_key_expiration_days', 14, 365, 90),
    ]

    if request.method == 'POST':
        changes = []

        # Timezone
        tz = request.POST.get('timezone', 'UTC')
        if tz in available_timezones and tz != app_settings.timezone:
            app_settings.timezone = tz
            changes.append(f'timezone={tz}')
        if tz in available_timezones:
            app_settings.timezone_configured = True

        # Timestamp format
        ts_format = request.POST.get('timestamp_format', 'Y-m-d H:i:s')
        if ts_format in valid_ts_formats and ts_format != app_settings.timestamp_format:
            app_settings.timestamp_format = ts_format
            changes.append(f'timestamp_format={ts_format}')

        # Integer fields
        for field_name, attr_name, min_val, max_val, default in int_fields:
            try:
                val = int(request.POST.get(field_name, default))
                val = max(min_val, min(val, max_val))
            except (ValueError, TypeError):
                val = default
            old_val = getattr(app_settings, attr_name)
            if val != old_val:
                setattr(app_settings, attr_name, val)
                changes.append(f'{attr_name}={val}')

        # Syslog settings
        new_syslog_enabled = request.POST.get('syslog_enabled') == 'on'
        new_syslog_host = request.POST.get('syslog_host', '').strip()
        new_syslog_port = request.POST.get('syslog_port', '514')
        new_syslog_protocol = request.POST.get('syslog_protocol', 'udp')
        try:
            new_syslog_port = max(1, min(int(new_syslog_port), 65535))
        except (ValueError, TypeError):
            new_syslog_port = 514

        if new_syslog_enabled != app_settings.syslog_enabled:
            app_settings.syslog_enabled = new_syslog_enabled
            changes.append(f'syslog_enabled={new_syslog_enabled}')
        if new_syslog_host != app_settings.syslog_host:
            app_settings.syslog_host = new_syslog_host
            changes.append(f'syslog_host={new_syslog_host}')
        if new_syslog_port != app_settings.syslog_port:
            app_settings.syslog_port = new_syslog_port
            changes.append(f'syslog_port={new_syslog_port}')
        if new_syslog_protocol in ('udp', 'tcp') and new_syslog_protocol != app_settings.syslog_protocol:
            app_settings.syslog_protocol = new_syslog_protocol
            changes.append(f'syslog_protocol={new_syslog_protocol}')

        # EDL delete protection
        new_edl_delete_protection = request.POST.get('edl_delete_protection') == 'on'
        if new_edl_delete_protection != app_settings.edl_delete_protection:
            app_settings.edl_delete_protection = new_edl_delete_protection
            changes.append(f'edl_delete_protection={new_edl_delete_protection}')

        for field_name, min_val, max_val, default in [
            ('edl_delete_threshold', 1, 100, 3),
            ('edl_delete_window_minutes', 5, 1440, 15),
        ]:
            try:
                val = int(request.POST.get(field_name, default))
                val = max(min_val, min(val, max_val))
            except (ValueError, TypeError):
                val = default
            old_val = getattr(app_settings, field_name)
            if val != old_val:
                setattr(app_settings, field_name, val)
                changes.append(f'{field_name}={val}')

        # Auto-block settings
        new_autoblock_enabled = request.POST.get('autoblock_enabled') == 'on'
        if new_autoblock_enabled != app_settings.autoblock_enabled:
            app_settings.autoblock_enabled = new_autoblock_enabled
            changes.append(f'autoblock_enabled={new_autoblock_enabled}')

        for field_name, min_val, max_val, default in [
            ('autoblock_threshold', 3, 1000, 50),
            ('autoblock_window_seconds', 10, 3600, 60),
            ('autoblock_duration_minutes', 0, 525600, 0),
            ('autoblock_long_threshold', 0, 10000, 30),
            ('autoblock_long_window_hours', 1, 720, 24),
        ]:
            try:
                val = int(request.POST.get(field_name, default))
                val = max(min_val, min(val, max_val))
            except (ValueError, TypeError):
                val = default
            old_val = getattr(app_settings, field_name)
            if val != old_val:
                setattr(app_settings, field_name, val)
                changes.append(f'{field_name}={val}')

        # Failed-login block settings
        new_fl_enabled = request.POST.get('failed_login_block_enabled') == 'on'
        if new_fl_enabled != app_settings.failed_login_block_enabled:
            app_settings.failed_login_block_enabled = new_fl_enabled
            changes.append(f'failed_login_block_enabled={new_fl_enabled}')

        for field_name, min_val, max_val, default in [
            ('failed_login_block_threshold', 1, 100, 3),
            ('failed_login_warning_threshold', 1, 100, 2),
            ('failed_login_window_hours', 1, 720, 24),
        ]:
            try:
                val = int(request.POST.get(field_name, default))
                val = max(min_val, min(val, max_val))
            except (ValueError, TypeError):
                val = default
            old_val = getattr(app_settings, field_name)
            if val != old_val:
                setattr(app_settings, field_name, val)
                changes.append(f'{field_name}={val}')

        # Email / File settings
        new_resend_key = request.POST.get('mail_service_token', '').strip()
        if new_resend_key != app_settings.resend_api_key:
            app_settings.resend_api_key = new_resend_key
            changes.append('resend_api_key=***')

        new_from_name = request.POST.get('resend_from_name', '').strip()
        if new_from_name != app_settings.resend_from_name:
            app_settings.resend_from_name = new_from_name
            changes.append(f'resend_from_name={new_from_name}')

        new_from_email = request.POST.get('resend_from_email', '').strip()
        if new_from_email != app_settings.resend_from_email:
            app_settings.resend_from_email = new_from_email
            changes.append(f'resend_from_email={new_from_email}')

        try:
            new_max_file = int(request.POST.get('max_file_size_mb', 250))
            new_max_file = max(1, min(new_max_file, 1000))
        except (ValueError, TypeError):
            new_max_file = 250
        if new_max_file != app_settings.max_file_size_mb:
            app_settings.max_file_size_mb = new_max_file
            changes.append(f'max_file_size_mb={new_max_file}')

        # Branding
        for field in ['otf_brand_name', 'otf_brand_bg_color', 'otf_brand_text_color', 'otf_brand_card_color', 'otf_brand_card_text_color']:
            new_val = request.POST.get(field, '').strip()
            if new_val and new_val != getattr(app_settings, field):
                setattr(app_settings, field, new_val)
                changes.append(f'{field}={new_val}')

        # robots.txt body
        new_robots = request.POST.get('robots_txt', '')
        if new_robots != app_settings.robots_txt:
            app_settings.robots_txt = new_robots
            changes.append('robots_txt=updated')

        # Backup schedule
        new_backup_time_raw = request.POST.get('backup_time', '').strip()
        if new_backup_time_raw:
            try:
                hh, mm = new_backup_time_raw.split(':')[:2]
                from datetime import time as _dtime
                new_backup_time = _dtime(int(hh), int(mm))
                if new_backup_time != app_settings.backup_time:
                    app_settings.backup_time = new_backup_time
                    changes.append(f'backup_time={new_backup_time.strftime("%H:%M")}')
            except (ValueError, TypeError):
                pass

        # Backblaze B2
        new_b2_enabled = request.POST.get('b2_enabled') == 'on'
        if new_b2_enabled != app_settings.b2_enabled:
            app_settings.b2_enabled = new_b2_enabled
            changes.append(f'b2_enabled={new_b2_enabled}')

        new_b2_key_id = request.POST.get('b2_application_key_id', '').strip()
        if new_b2_key_id != app_settings.b2_application_key_id:
            app_settings.b2_application_key_id = new_b2_key_id
            changes.append(f'b2_application_key_id={new_b2_key_id}')

        new_b2_key = request.POST.get('b2_application_key', '').strip()
        if new_b2_key and new_b2_key != app_settings.b2_application_key:
            app_settings.b2_application_key = new_b2_key
            changes.append('b2_application_key=***')

        new_b2_bucket = request.POST.get('b2_bucket_name', '').strip()
        if new_b2_bucket != app_settings.b2_bucket_name:
            app_settings.b2_bucket_name = new_b2_bucket
            changes.append(f'b2_bucket_name={new_b2_bucket}')

        if 'otf_brand_image' in request.FILES:
            logo = request.FILES['otf_brand_image']
            if logo.size > 2 * 1024 * 1024:  # 2MB
                messages.error(request, 'Logo image must be under 2MB.')
            else:
                # Delete old logo file before saving new one
                if app_settings.otf_brand_image:
                    try:
                        app_settings.otf_brand_image.delete(save=False)
                    except Exception:
                        pass
                app_settings.otf_brand_image = logo
                changes.append('otf_brand_image=updated')

        app_settings.save()

        # Apply session timeout
        from django.conf import settings as django_settings
        django_settings.SESSION_COOKIE_AGE = app_settings.session_timeout_minutes * 60

        if changes:
            log_activity(request, 'update_settings', '; '.join(changes))
            messages.success(request, 'Settings updated.')
        else:
            messages.info(request, 'No changes.')
        return redirect('app:app_settings')

    # List available data backups
    backup_dir = Path(settings.BASE_DIR) / 'backups' / 'data'
    backups = []
    if backup_dir.exists():
        for f in sorted(backup_dir.glob('backup_*.tar.gz'), reverse=True):
            # Parse timestamp from filename: backup_YYYYMMDDHHMMSS.tar.gz
            ts_str = f.stem.replace('backup_', '').replace('.tar', '')
            try:
                ts = datetime.strptime(ts_str, '%Y%m%d%H%M%S').replace(tzinfo=timezone.utc)
            except ValueError:
                ts = None
            backups.append({'filename': f.name, 'timestamp': ts})

    return render(request, 'app_settings.html', {
        'app_settings': app_settings,
        'timezones': available_timezones,
        'data_backups': backups,
    })


@login_required
@require_http_methods(["POST"])
def restore_data_view(request):
    """Restore EDLs and URLs from a backup archive."""
    if not request.user.is_superuser:
        raise PermissionDenied

    archive = request.POST.get('archive', '').strip()
    if not archive or '/' in archive or '..' in archive:
        messages.error(request, 'Invalid backup selection.')
        return redirect('app:app_settings')

    try:
        from django.core.management import call_command
        from io import StringIO
        out = StringIO()
        call_command('restore_data', archive, stdout=out)
        log_activity(request, 'restore_data', archive, out.getvalue()[:500])
        messages.success(request, f'Data restored from {archive}.')
    except Exception as e:
        messages.error(request, f'Restore failed: {e}')

    return redirect('app:app_settings')


@login_required
@require_http_methods(["POST"])
def backup_to_b2_view(request):
    """Upload the most recent local backup tarball to Backblaze B2."""
    if not request.user.is_superuser:
        raise PermissionDenied

    from . import b2_backup
    app_settings = AppSettings.objects.get(pk=1)

    if not app_settings.b2_enabled:
        messages.error(request, 'B2 backup is not enabled. Configure it in Settings first.')
        return redirect('app:app_settings')

    latest = b2_backup.latest_backup_path(settings.BASE_DIR)
    if not latest:
        messages.error(request, 'No local backup found to upload. Run a backup first.')
        return redirect('app:app_settings')

    success, message = b2_backup.upload_file(latest, app_settings)
    app_settings.save()
    log_activity(request, 'backup_to_b2', latest.name, message[:500])
    if success:
        messages.success(request, message)
    else:
        messages.error(request, f'B2 upload failed: {message}')
    return redirect('app:app_settings')


@login_required
def user_list_view(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    users = CustomUser.objects.all().order_by('email')
    groups = Group.objects.all().order_by('name')
    return render(request, 'user_list.html', {'users': users, 'groups': groups})


@login_required
def user_create_view(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    groups = Group.objects.all().order_by('name')
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        password = request.POST.get('password', '')
        selected_groups = request.POST.getlist('groups')
        # Superuser/staff derived from group membership
        superuser_group = Group.objects.filter(name='Superuser').first()
        is_superuser = superuser_group and str(superuser_group.id) in selected_groups
        is_staff = is_superuser

        if not email or not password:
            messages.error(request, 'Email and password are required.')
            return render(request, 'user_form.html', {'groups': groups, 'mode': 'create'})

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, 'A user with that email already exists.')
            return render(request, 'user_form.html', {'groups': groups, 'mode': 'create'})

        user = CustomUser.objects.create_user(
            email=email, password=password,
            first_name=first_name, last_name=last_name,
            is_staff=is_staff, is_superuser=is_superuser,
        )
        user.groups.set(Group.objects.filter(id__in=selected_groups))
        group_names = list(Group.objects.filter(id__in=selected_groups).values_list('name', flat=True))
        detail_parts = []
        if first_name or last_name:
            detail_parts.append(f'Name: {first_name} {last_name}'.strip())
        if is_staff:
            detail_parts.append('is_staff=True')
        if is_superuser:
            detail_parts.append('is_superuser=True')
        if group_names:
            detail_parts.append(f'Groups: {", ".join(group_names)}')
        log_activity(request, 'create_user', email, '; '.join(detail_parts))
        messages.success(request, f'User {email} created.')
        return redirect('app:user_list')

    return render(request, 'user_form.html', {'groups': groups, 'mode': 'create'})


@login_required
@login_required
@require_http_methods(["POST"])
def user_delete_view(request, user_id):
    """Delete a user, reassigning their EDLs and URLs to the next oldest account."""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Forbidden'}, status=403)

    target_user = get_object_or_404(CustomUser, id=user_id)

    # Can't delete yourself
    if target_user == request.user:
        return JsonResponse({'error': 'Cannot delete your own account'}, status=400)

    # Find the next oldest user to reassign to (excluding the target)
    reassign_to = CustomUser.objects.exclude(id=target_user.id).order_by('date_joined').first()
    if not reassign_to:
        return JsonResponse({'error': 'Cannot delete the last user'}, status=400)

    # Reassign EDLs
    edl_count = ExtDynLists.objects.filter(groups__in=target_user.groups.all()).count()

    # Reassign shortened URLs
    url_count = ShortenedURL.objects.filter(created_by=target_user).update(created_by=reassign_to)

    # Reassign favorites
    Favorite.objects.filter(user=target_user).update(user=reassign_to)

    email = target_user.email
    target_user.delete()

    log_activity(request, 'delete_user', email, f'Reassigned {url_count} URLs to {reassign_to.email}')
    return JsonResponse({'status': 'deleted', 'reassigned_to': reassign_to.email})


@login_required
def user_edit_view(request, user_id):
    """Edit a user. Superusers can edit anyone; non-superusers can only edit themselves.

    Self-editing non-superusers can change first/last name, password, and
    regenerate their API key (if their group has the `users.use_api_key`
    permission). They cannot change group membership or active status.
    """
    edit_user = get_object_or_404(CustomUser, id=user_id)
    is_self = request.user.id == edit_user.id
    if not (request.user.is_superuser or is_self):
        raise PermissionDenied

    groups = Group.objects.all().order_by('name')
    can_use_api_key = edit_user.has_perm('users.use_api_key')

    if request.method == 'POST':
        # API-key regeneration is its own POST branch (button name)
        if 'generate_api_key' in request.POST:
            if not can_use_api_key:
                messages.error(request, 'This user does not have permission to use an API key.')
                return redirect('app:user_edit', user_id=user_id)
            APIKey.objects.filter(user=edit_user).delete()
            generate_api_key(edit_user)
            actor_note = '' if is_self else f' for {edit_user.email}'
            log_activity(request, 'generate_api_key', edit_user.email, f'Regenerated{actor_note}')
            messages.success(request, 'New API key generated.')
            return redirect('app:user_edit', user_id=user_id)

        # Snapshot before state
        before = {
            'first_name': edit_user.first_name,
            'last_name': edit_user.last_name,
            'is_active': edit_user.is_active,
            'is_superuser': edit_user.is_superuser,
            'groups': set(edit_user.groups.values_list('name', flat=True)),
        }

        edit_user.first_name = request.POST.get('first_name', '').strip()
        edit_user.last_name = request.POST.get('last_name', '').strip()

        # Group + active changes — superuser only
        if request.user.is_superuser:
            new_is_active = request.POST.get('is_active') == 'on'
            selected_groups = request.POST.getlist('groups')
            superuser_group = Group.objects.filter(name='Superuser').first()
            new_is_superuser = bool(superuser_group and str(superuser_group.id) in selected_groups)

            # Protect last superuser
            is_last_superuser = edit_user.is_superuser and CustomUser.objects.filter(is_superuser=True).count() == 1
            if is_last_superuser and (not new_is_superuser or not new_is_active):
                messages.error(request, 'Cannot remove the last user from the Superuser group or deactivate them.')
                return redirect('app:user_edit', user_id=user_id)

            edit_user.is_active = new_is_active
            edit_user.is_superuser = new_is_superuser
            edit_user.is_staff = new_is_superuser

        # Password change (optional, allowed for self or superuser)
        changes = []
        new_password = request.POST.get('password', '').strip()
        if new_password:
            edit_user.set_password(new_password)
            changes.append('Password changed')

        edit_user.save()

        if request.user.is_superuser:
            new_groups = set(Group.objects.filter(id__in=selected_groups).values_list('name', flat=True))
            edit_user.groups.set(Group.objects.filter(id__in=selected_groups))
            for flag in ['is_active', 'is_superuser']:
                new_val = getattr(edit_user, flag)
                if before[flag] != new_val:
                    changes.append(f'{flag}: {before[flag]} -> {new_val}')
            added_groups = new_groups - before['groups']
            removed_groups = before['groups'] - new_groups
            if added_groups:
                changes.append(f'Added groups: {", ".join(sorted(added_groups))}')
            if removed_groups:
                changes.append(f'Removed groups: {", ".join(sorted(removed_groups))}')

        for field in ['first_name', 'last_name']:
            new_val = getattr(edit_user, field)
            if before[field] != new_val:
                changes.append(f'{field}: {before[field]!r} -> {new_val!r}')

        detail = '; '.join(changes) if changes else 'No changes'
        log_activity(request, 'edit_user', edit_user.email, detail)
        messages.success(request, f'{"Your account" if is_self else f"User {edit_user.email}"} updated.')
        if is_self:
            return redirect('app:user_edit', user_id=user_id)
        return redirect('app:user_list')

    api_key_obj = APIKey.objects.filter(user=edit_user).first() if can_use_api_key else None
    return render(request, 'user_form.html', {
        'edit_user': edit_user,
        'groups': groups,
        'mode': 'edit',
        'is_self': is_self,
        'can_use_api_key': can_use_api_key,
        'api_key': api_key_obj.key if api_key_obj else None,
    })


@login_required
def group_list_view(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    groups = Group.objects.all().order_by('name')

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'delete':
            group_id = request.POST.get('group_id')
            group = get_object_or_404(Group, id=group_id)
            if group.name == 'Superuser':
                messages.error(request, 'The Superuser group cannot be deleted.')
            elif group.user_set.exists():
                messages.error(request, f'Cannot delete "{group.name}" — it still has members.')
            else:
                log_activity(request, 'delete_group', group.name)
                group.delete()
                messages.success(request, 'Group deleted.')
        return redirect('app:group_list')

    return render(request, 'group_list.html', {'groups': groups})


@login_required
def group_create_view(request):
    if not request.user.is_superuser:
        raise PermissionDenied

    app_content_types = ContentType.objects.filter(app_label__in=['app', 'users'])
    available_permissions = Permission.objects.filter(
        content_type__in=app_content_types
    ).exclude(
        content_type__model='activitylog', codename__in=['add_activitylog', 'change_activitylog', 'delete_activitylog']
    ).order_by('content_type__model', 'codename')
    all_users = CustomUser.objects.filter(is_active=True).order_by('email')

    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        if not name:
            messages.error(request, 'Group name is required.')
            return render(request, 'group_edit.html', {
                'available_permissions': available_permissions,
                'all_users': all_users,
                'mode': 'create',
            })
        if Group.objects.filter(name=name).exists():
            messages.error(request, f'Group "{name}" already exists.')
            return render(request, 'group_edit.html', {
                'available_permissions': available_permissions,
                'all_users': all_users,
                'mode': 'create',
            })

        group = Group.objects.create(name=name)

        selected_perms = request.POST.getlist('permissions')
        group.permissions.set(Permission.objects.filter(id__in=selected_perms))

        selected_members = request.POST.getlist('members')
        for user in CustomUser.objects.filter(id__in=selected_members):
            user.groups.add(group)

        detail_parts = []
        if selected_perms:
            detail_parts.append(f'{len(selected_perms)} permissions')
        if selected_members:
            member_emails = list(CustomUser.objects.filter(id__in=selected_members).values_list('email', flat=True))
            detail_parts.append(f'Members: {", ".join(member_emails)}')
        log_activity(request, 'create_group', name, '; '.join(detail_parts))
        messages.success(request, f'Group "{name}" created.')
        return redirect('app:group_list')

    return render(request, 'group_edit.html', {
        'available_permissions': available_permissions,
        'all_users': all_users,
        'mode': 'create',
    })


@login_required
def group_edit_view(request, group_id):
    if not request.user.is_superuser:
        raise PermissionDenied
    group = get_object_or_404(Group, id=group_id)

    # Get app-relevant permissions only
    app_content_types = ContentType.objects.filter(app_label__in=['app', 'users'])
    available_permissions = Permission.objects.filter(
        content_type__in=app_content_types
    ).exclude(
        content_type__model='activitylog', codename__in=['add_activitylog', 'change_activitylog', 'delete_activitylog']
    ).order_by('content_type__model', 'codename')

    # Also get all users for member management
    all_users = CustomUser.objects.filter(is_active=True).order_by('email')

    if request.method == 'POST':
        before_name = group.name
        before_perms = set(group.permissions.values_list('codename', flat=True))
        before_members = set(group.user_set.values_list('email', flat=True))

        # Update name (Superuser group cannot be renamed)
        new_name = request.POST.get('name', '').strip()
        if new_name and new_name != group.name:
            if group.name == 'Superuser':
                messages.error(request, 'The Superuser group cannot be renamed.')
                return redirect('app:group_edit', group_id=group.id)
            if Group.objects.filter(name=new_name).exclude(id=group.id).exists():
                messages.error(request, f'Group "{new_name}" already exists.')
                return redirect('app:group_edit', group_id=group.id)
            group.name = new_name

        # Update permissions
        selected_perms = request.POST.getlist('permissions')
        group.permissions.set(Permission.objects.filter(id__in=selected_perms))

        # Update members
        selected_members = request.POST.getlist('members')
        current_members = set(group.user_set.values_list('id', flat=True))
        new_member_ids = set(int(m) for m in selected_members)
        # Add new members
        for user in CustomUser.objects.filter(id__in=new_member_ids - current_members):
            user.groups.add(group)
        # Remove old members
        for user in CustomUser.objects.filter(id__in=current_members - new_member_ids):
            user.groups.remove(group)

        group.save()

        # Log changes
        changes = []
        if group.name != before_name:
            changes.append(f'Renamed: {before_name} -> {group.name}')
        after_perms = set(group.permissions.values_list('codename', flat=True))
        added_perms = after_perms - before_perms
        removed_perms = before_perms - after_perms
        if added_perms:
            changes.append(f'Added perms: {", ".join(sorted(added_perms))}')
        if removed_perms:
            changes.append(f'Removed perms: {", ".join(sorted(removed_perms))}')
        after_members = set(group.user_set.values_list('email', flat=True))
        added_members = after_members - before_members
        removed_members = before_members - after_members
        if added_members:
            changes.append(f'Added members: {", ".join(sorted(added_members))}')
        if removed_members:
            changes.append(f'Removed members: {", ".join(sorted(removed_members))}')

        detail = '; '.join(changes) if changes else 'No changes'
        log_activity(request, 'edit_group', group.name, detail)
        messages.success(request, f'Group "{group.name}" updated.')
        return redirect('app:group_list')

    return render(request, 'group_edit.html', {
        'group': group,
        'available_permissions': available_permissions,
        'all_users': all_users,
    })


def get_current_version():
    version_file = Path(settings.BASE_DIR) / 'VERSION'
    try:
        return version_file.read_text().strip()
    except FileNotFoundError:
        return 'unknown'


def get_remote_version():
    """Check the remote branch's VERSION file via git. Returns None on failure."""
    base_dir = str(settings.BASE_DIR)
    try:
        subprocess.run(
            ['git', 'fetch'], cwd=base_dir, capture_output=True, text=True, timeout=10,
        )
        result = subprocess.run(
            ['git', 'show', 'origin/main:VERSION'], cwd=base_dir, capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


@login_required
def upgrade_view(request):
    if not request.user.is_superuser:
        raise PermissionDenied

    current_version = get_current_version()
    latest_version = get_remote_version()
    upgrade_available = (
        latest_version is not None
        and current_version != 'unknown'
        and latest_version != current_version
    )

    from app.models import AppSettings
    deployment_mode = AppSettings.load().deployment_mode

    # Check if sudoers rules are complete
    sudoers_ok = True
    result = subprocess.run(
        ['sudo', '-n', 'nginx', '-t'], capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0 and 'password is required' in result.stderr.lower():
        sudoers_ok = False

    context = {
        'current_version': current_version,
        'latest_version': latest_version,
        'upgrade_available': upgrade_available,
        'legacy_deployment': deployment_mode == 'gunicorn_ssl',
        'sudoers_incomplete': not sudoers_ok,
        'title': 'System Upgrade',
    }

    if request.method == 'POST':
        if not upgrade_available:
            messages.info(request, 'Already up to date.')
            return redirect('app:upgrade')

        base_dir = str(settings.BASE_DIR)
        python = sys.executable
        manage_py = os.path.join(base_dir, 'manage.py')
        success = True

        # Step 0: Back up database
        db_path = os.path.join(base_dir, 'db.sqlite3')
        if os.path.exists(db_path):
            backup_dir = os.path.join(base_dir, 'backups')
            os.makedirs(backup_dir, exist_ok=True)
            backup_file = os.path.join(backup_dir, f'db.sqlite3.{datetime.now().strftime("%Y%m%d%H%M%S")}.bak')
            import shutil
            shutil.copy2(db_path, backup_file)
            logger.info(f"Database backed up to {backup_file}")

            # Prune backups older than 30 days
            cutoff_ts = datetime.now().timestamp() - (30 * 86400)
            for f in Path(backup_dir).glob('db.sqlite3.*.bak'):
                if f.stat().st_mtime < cutoff_ts:
                    f.unlink()

        # Step 1: git pull — protect state files (db, env, blocklist.conf) from older
        # installs that still track them. These files represent operator state and
        # must not be touched by the pull.
        db_protect = os.path.join(base_dir, 'db.sqlite3.upgrade_protect')
        env_protect = os.path.join(base_dir, 'project', '.env.upgrade_protect')
        blocklist_path = os.path.join(base_dir, 'deploy', 'blocklist.conf')
        blocklist_protect = os.path.join(base_dir, 'deploy', 'blocklist.conf.upgrade_protect')
        import shutil as _shutil
        if Path(db_path).exists():
            _shutil.copy2(db_path, db_protect)
        env_path = Path(base_dir) / 'project' / '.env'
        if env_path.exists():
            _shutil.copy2(env_path, env_protect)
        if os.path.exists(blocklist_path):
            _shutil.copy2(blocklist_path, blocklist_protect)

        # Drop local tracked-file changes so pull can't conflict
        subprocess.run(['git', 'checkout', '--', '.'], cwd=base_dir, capture_output=True)
        result = subprocess.run(
            ['git', 'pull'], cwd=base_dir, capture_output=True, text=True,
        )

        # Restore protected files regardless of pull outcome
        if os.path.exists(db_protect):
            os.replace(db_protect, db_path)
        if os.path.exists(env_protect):
            os.replace(env_protect, env_path)
        if os.path.exists(blocklist_protect):
            os.replace(blocklist_protect, blocklist_path)

        if result.returncode != 0:
            messages.error(request, 'Upgrade failed. Please try again or upgrade manually.')
            logger.error(f"Upgrade git pull failed for {request.user.email}: {result.stderr.strip()}")
            return redirect('app:upgrade')

        # Step 2: pip install
        pip = os.path.join(os.path.dirname(python), 'pip')
        result = subprocess.run(
            [pip, 'install', '-r', os.path.join(base_dir, 'requirements.txt')],
            cwd=base_dir, capture_output=True, text=True,
        )
        if result.returncode != 0:
            success = False
            logger.error(f"Upgrade pip install failed for {request.user.email}: {result.stderr.strip()}")

        # Step 3: migrate
        result = subprocess.run(
            [python, manage_py, 'migrate', '--noinput'], cwd=base_dir, capture_output=True, text=True,
        )
        if result.returncode != 0:
            success = False
            logger.error(f"Upgrade migrate failed for {request.user.email}: {result.stderr.strip()}")

        # Step 4: collectstatic
        result = subprocess.run(
            [python, manage_py, 'collectstatic', '--noinput'], cwd=base_dir, capture_output=True, text=True,
        )
        if result.returncode != 0:
            success = False
            logger.error(f"Upgrade collectstatic failed for {request.user.email}: {result.stderr.strip()}")

        log_activity(request, 'upgrade', f'v{current_version}', 'Code updated, restarting')

        if not success:
            # git pull/migrate/collectstatic had errors — return JSON so JS knows
            return JsonResponse({'status': 'error', 'message': 'Upgrade completed with errors. Check server logs.'})

        # Step 5: Patch Nginx config if needed, then restart
        patch_cmds = ''
        nginx_conf = None
        for path_candidate in [
            '/etc/nginx/sites-available/kineticlull',
            '/etc/nginx/conf.d/kineticlull.conf',
        ]:
            if os.path.exists(path_candidate):
                nginx_conf = path_candidate
                break

        if nginx_conf:
            try:
                with open(nginx_conf, 'r') as f:
                    nginx_content = f.read()
                if 'client_max_body_size' not in nginx_content:
                    patch_cmds += f"sudo -n sed -i '/ssl_session_timeout/a\\\\    client_max_body_size 260m;' {nginx_conf}; "
                if 'media/branding' not in nginx_content:
                    media_block = (
                        f"    # Branding images\\n"
                        f"    location /media/branding/ {{\\n"
                        f"        alias {base_dir}/media/branding/;\\n"
                        f"        expires 1d;\\n"
                        f"        access_log off;\\n"
                        f"    }}\\n"
                    )
                    patch_cmds += f"sudo -n sed -i '/location \\/static\\//i\\{media_block}' {nginx_conf}; "
            except Exception:
                pass

        os.makedirs(os.path.join(base_dir, 'media', 'branding'), exist_ok=True)

        # Ensure blocklist file exists — nginx config `include`s it.
        blocklist_file = os.path.join(base_dir, 'deploy', 'blocklist.conf')
        if not os.path.exists(blocklist_file):
            os.makedirs(os.path.dirname(blocklist_file), exist_ok=True)
            open(blocklist_file, 'a').close()

        # Apply any nginx config patches first (runs in our own process, before
        # the cgroup gets SIGTERM'd).
        if patch_cmds:
            subprocess.run(['bash', '-c', patch_cmds], capture_output=True)

        # Hand the restart off to systemd via /usr/local/bin/kl-restart, which
        # uses `systemd-run` to launch the actual restart commands in a NEW
        # transient unit with its own cgroup. This survives systemd killing
        # the kineticlull cgroup we're currently running in.
        if not os.path.exists('/usr/local/bin/kl-restart'):
            return JsonResponse({
                'status': 'error',
                'message': 'Restart helper missing at /usr/local/bin/kl-restart. Run `bash upgrade.sh` on the server once to install it, then try again.',
            })
        r = subprocess.run(
            ['sudo', '-n', '/usr/local/bin/kl-restart'],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return JsonResponse({
                'status': 'error',
                'message': f'Restart helper failed (rc={r.returncode}). Run `bash upgrade.sh` on the server to reinstall the sudoers rule, then try again.\n\n{(r.stderr or "").strip()}',
            })
        return JsonResponse({'status': 'ok', 'message': 'Restarting...'})

    return render(request, 'upgrade.html', context)


@login_required
@require_http_methods(["POST"])
def restart_services_view(request):
    """Restart KineticLull and Nginx via the web UI."""
    if not request.user.is_superuser:
        raise PermissionDenied

    # Check if sudoers rules are in place before attempting restart
    result = subprocess.run(
        ['sudo', '-n', 'systemctl', 'status', 'kineticlull'],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0 and 'password is required' in result.stderr.lower():
        return JsonResponse({
            'status': 'error',
            'message': 'Sudoers rules not configured. Run "bash upgrade.sh" once from the command line.',
        })

    base_dir = str(settings.BASE_DIR)
    python = sys.executable
    manage_py = os.path.join(base_dir, 'manage.py')

    # Collect static files before restart
    cs_result = subprocess.run(
        [python, manage_py, 'collectstatic', '--noinput'],
        cwd=base_dir, capture_output=True, text=True,
    )
    if cs_result.returncode != 0:
        logger.error(f"collectstatic failed: {cs_result.stderr.strip()}")

    # Patch Nginx config if needed (media/branding, client_max_body_size)
    nginx_conf = None
    for path_candidate in [
        '/etc/nginx/sites-available/kineticlull',
        '/etc/nginx/conf.d/kineticlull.conf',
    ]:
        if os.path.exists(path_candidate):
            nginx_conf = path_candidate
            break

    if nginx_conf:
        try:
            with open(nginx_conf, 'r') as f:
                nginx_content = f.read()

            nginx_changed = False

            if 'client_max_body_size' not in nginx_content:
                subprocess.run(
                    ['sudo', '-n', 'sed', '-i', '/ssl_session_timeout/a\\    client_max_body_size 260m;', nginx_conf],
                    capture_output=True, text=True,
                )
                nginx_changed = True
                logger.info("Patched Nginx: added client_max_body_size")

            if 'media/branding' not in nginx_content:
                media_block = (
                    f"    # Branding images\\n"
                    f"    location /media/branding/ {{\\n"
                    f"        alias {base_dir}/media/branding/;\\n"
                    f"        expires 1d;\\n"
                    f"        access_log off;\\n"
                    f"    }}\\n"
                )
                subprocess.run(
                    ['sudo', '-n', 'sed', '-i', f'/location \\/static\\//i\\{media_block}', nginx_conf],
                    capture_output=True, text=True,
                )
                nginx_changed = True
                logger.info("Patched Nginx: added /media/branding/ location")

            if nginx_changed:
                result = subprocess.run(['sudo', '-n', 'nginx', '-t'], capture_output=True, text=True)
                if result.returncode != 0:
                    logger.error(f"Nginx config test failed after patching: {result.stderr.strip()}")
        except Exception as e:
            logger.error(f"Nginx config patching failed: {e}")

    # Ensure media/branding directory exists
    os.makedirs(os.path.join(base_dir, 'media', 'branding'), exist_ok=True)

    log_activity(request, 'restart_services', '', 'Manual restart from web UI')
    if not os.path.exists('/usr/local/bin/kl-restart'):
        return JsonResponse({
            'status': 'error',
            'message': 'Restart helper missing at /usr/local/bin/kl-restart. Run `bash upgrade.sh` on the server once to install it.',
        })
    r = subprocess.run(
        ['sudo', '-n', '/usr/local/bin/kl-restart'],
        capture_output=True, text=True, timeout=5,
    )
    if r.returncode != 0:
        return JsonResponse({
            'status': 'error',
            'message': f'Restart failed (rc={r.returncode}). {(r.stderr or "").strip()}',
        })
    return JsonResponse({'status': 'ok'})


@login_required
def deployment_status_view(request):
    if not request.user.is_superuser:
        raise PermissionDenied

    from app.models import AppSettings
    import shutil

    app_settings = AppSettings.load()
    db_mode = app_settings.deployment_mode

    # System-level checks
    nginx_installed = shutil.which('nginx') is not None
    nginx_active = False
    nginx_config_exists = False
    service_mode = 'unknown'

    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'nginx'],
            capture_output=True, text=True, timeout=5,
        )
        nginx_active = result.stdout.strip() == 'active'
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Check for nginx config
    for path in ['/etc/nginx/sites-available/kineticlull', '/etc/nginx/conf.d/kineticlull.conf']:
        if os.path.exists(path):
            nginx_config_exists = True
            break

    # Check systemd service
    service_file = '/etc/systemd/system/kineticlull.service'
    if os.path.exists(service_file):
        try:
            with open(service_file, 'r') as f:
                svc_content = f.read()
            if 'authbind' in svc_content or '--certfile' in svc_content:
                service_mode = 'gunicorn_ssl'
            elif '127.0.0.1:8000' in svc_content:
                service_mode = 'nginx_gunicorn'
        except PermissionError:
            pass

    # Determine effective mode and any mismatch
    effective_mode = db_mode
    mismatch = False
    if service_mode != 'unknown' and service_mode != db_mode:
        mismatch = True
        effective_mode = service_mode

    # Python environment info
    import platform
    from importlib.metadata import distributions
    python_version = platform.python_version()
    installed_packages = sorted(
        [{'name': d.metadata['Name'], 'version': d.metadata['Version']} for d in distributions()],
        key=lambda x: x['name'].lower()
    )

    context = {
        'title': 'Deployment',
        'deployment_mode': effective_mode,
        'deployment_label': dict(AppSettings.DEPLOYMENT_CHOICES).get(effective_mode, effective_mode),
        'nginx_installed': nginx_installed,
        'nginx_active': nginx_active,
        'nginx_config_exists': nginx_config_exists,
        'mismatch': mismatch,
        'db_mode': db_mode,
        'service_mode': service_mode,
        'can_migrate': effective_mode == 'gunicorn_ssl',
        'python_version': python_version,
        'installed_packages': installed_packages,
    }
    return render(request, 'deployment_status.html', context)


@login_required
def system_health_view(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    from . import health
    if request.method == 'POST':
        fix_id = request.POST.get('fix_id', '').strip()
        ok, output = health.run_fix(fix_id)
        log_activity(request, 'system_health_fix', target=fix_id, detail=('ok' if ok else 'failed'))
        return JsonResponse({'ok': ok, 'output': output})
    checks = health.run_all(force=True)
    return render(request, 'system_health.html', {'checks': checks})


@login_required
def deployment_migrate_view(request):
    if not request.user.is_superuser:
        raise PermissionDenied

    from app.models import AppSettings
    base_dir = str(settings.BASE_DIR)

    # Pre-fill server name from .env
    kl_url = os.environ.get('KINETICLULL_URL', '')
    server_name = ''
    if kl_url:
        parsed = urlparse(kl_url)
        server_name = parsed.hostname or kl_url.replace('https://', '').replace('http://', '').strip('/')

    # Check for existing certs
    cert_dir = os.path.join(base_dir, 'ssl')
    has_ssl_certs = os.path.exists(os.path.join(cert_dir, 'cert.pem'))
    has_legacy_certs = os.path.exists(os.path.join(base_dir, 'cert.pem'))

    if request.method == 'POST':
        server_name = request.POST.get('server_name', server_name).strip()
        workers = request.POST.get('workers', '3').strip()
        confirmed = request.POST.get('confirmed') == 'on'
        ssl_mode = request.POST.get('ssl_mode', 'selfsigned').strip()
        letsencrypt_email = request.POST.get('letsencrypt_email', '').strip()
        if ssl_mode not in ('selfsigned', 'letsencrypt', 'existing'):
            ssl_mode = 'selfsigned'
        if has_ssl_certs or has_legacy_certs:
            ssl_mode = 'existing'

        if not server_name:
            messages.error(request, 'Server name is required.')
            return redirect('app:deployment_migrate')

        if not confirmed:
            messages.error(request, 'You must confirm you understand the migration requires sudo.')
            return redirect('app:deployment_migrate')

        # Strip protocol if user included it
        server_name = server_name.replace('https://', '').replace('http://', '').strip('/')

        try:
            workers = int(workers)
            if workers < 1 or workers > 16:
                workers = 3
        except ValueError:
            workers = 3

        # Generate the migration script
        deploy_dir = os.path.join(base_dir, 'deploy')
        script_path = os.path.join(deploy_dir, 'migrate_to_nginx.sh')

        # Read templates
        nginx_template_path = os.path.join(deploy_dir, 'nginx_kineticlull.conf.template')
        svc_template_path = os.path.join(deploy_dir, 'kineticlull.service.template')

        try:
            with open(nginx_template_path, 'r') as f:
                nginx_template = f.read()
            with open(svc_template_path, 'r') as f:
                svc_template = f.read()
        except FileNotFoundError as e:
            messages.error(request, f'Template file missing: {e.filename}')
            return redirect('app:deployment_migrate')

        cert_dir_path = os.path.join(base_dir, 'ssl')
        static_root = os.path.join(base_dir, 'staticfiles')
        venv_path = os.path.join(base_dir, 'venv')
        python_path = os.path.join(venv_path, 'bin', 'python')

        # Render nginx config
        nginx_config = nginx_template.replace('{{SERVER_NAME}}', server_name)
        nginx_config = nginx_config.replace('{{CERT_PATH}}', os.path.join(cert_dir_path, 'cert.pem'))
        nginx_config = nginx_config.replace('{{KEY_PATH}}', os.path.join(cert_dir_path, 'key.pem'))
        nginx_config = nginx_config.replace('{{STATIC_ROOT}}', static_root)
        nginx_config = nginx_config.replace('{{PROJECT_DIR}}', base_dir)

        # Render service file
        import getpass
        current_user = getpass.getuser()
        svc_config = svc_template.replace('{{USER}}', current_user)
        svc_config = svc_config.replace('{{PROJECT_DIR}}', base_dir)
        svc_config = svc_config.replace('{{VENV_PATH}}', venv_path)
        svc_config = svc_config.replace('{{WORKERS}}', str(workers))

        # Generate self-contained migration script
        script_content = _generate_migration_script(
            base_dir=base_dir,
            server_name=server_name,
            cert_dir=cert_dir_path,
            nginx_config=nginx_config,
            svc_config=svc_config,
            python_path=python_path,
            ssl_mode=ssl_mode,
            letsencrypt_email=letsencrypt_email,
            app_user=current_user,
        )

        os.makedirs(deploy_dir, exist_ok=True)
        with open(script_path, 'w') as f:
            f.write(script_content)
        os.chmod(script_path, 0o755)

        log_activity(request, 'deployment', 'nginx_migration', f'Migration script generated for {server_name}')

        context = {
            'title': 'Migration Script Ready',
            'script_path': script_path,
            'server_name': server_name,
            'generated': True,
        }
        return render(request, 'deployment_migrate.html', context)

    context = {
        'title': 'Migrate to Nginx',
        'server_name': server_name,
        'has_ssl_certs': has_ssl_certs,
        'has_legacy_certs': has_legacy_certs,
        'generated': False,
    }
    return render(request, 'deployment_migrate.html', context)


@login_required
def blocked_ips_view(request):
    if not request.user.is_superuser:
        raise PermissionDenied

    from django.utils import timezone
    from django.db.models import Count
    from datetime import timedelta

    # Clean up expired entries
    BlockedIP.objects.filter(expires_at__isnull=False, expires_at__lte=timezone.now()).delete()

    blocked_ips = BlockedIP.objects.all()

    # Get rejection counts per IP (last 30 days)
    rejection_counts = dict(
        NginxRejection.objects.filter(
            timestamp__gte=timezone.now() - timedelta(days=30)
        ).values_list('ip_address').annotate(count=Count('id')).values_list('ip_address', 'count')
    )

    # Get top paths per IP (last 5 unique paths from activity logs before block)
    top_paths = {}
    for entry in blocked_ips:
        paths = list(
            ActivityLog.objects.filter(
                ip_address=entry.ip_address,
                action__in=['not_found', 'edl_not_found'],
            ).order_by('-created_at').values_list('target', flat=True)[:10]
        )
        # Deduplicate while preserving order
        seen = set()
        unique_paths = []
        for p in paths:
            if p not in seen:
                seen.add(p)
                unique_paths.append(p)
                if len(unique_paths) >= 5:
                    break
        top_paths[entry.ip_address] = unique_paths

    # Annotate blocked_ips with extra data
    blocked_data = []
    for entry in blocked_ips:
        blocked_data.append({
            'entry': entry,
            'rejection_count': rejection_counts.get(entry.ip_address, 0),
            'top_paths': top_paths.get(entry.ip_address, []),
        })

    context = {
        'title': 'Blocked IPs',
        'blocked_data': blocked_data,
        'total_rejections': sum(rejection_counts.values()),
    }
    return render(request, 'blocked_ips.html', context)


@login_required
def whitelisted_ips_view(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    user_ip = get_client_ip(request)
    user_ip_whitelisted = WhitelistedIP.is_whitelisted(user_ip) if user_ip else False
    return render(request, 'whitelisted_ips.html', {
        'whitelisted_ips': WhitelistedIP.objects.all(),
        'user_ip': user_ip,
        'user_ip_whitelisted': user_ip_whitelisted,
    })


@login_required
@require_http_methods(["POST"])
def whitelist_ip_view(request):
    """Add an IP or subnet to the whitelist."""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Forbidden'}, status=403)

    ip = request.POST.get('ip_address', '').strip()
    reason = request.POST.get('reason', '').strip()

    if not ip:
        return JsonResponse({'error': 'IP address or subnet required'}, status=400)

    # Validate IP or CIDR
    try:
        if '/' in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
    except ValueError:
        return JsonResponse({'error': 'Invalid IP address or subnet'}, status=400)

    obj, created = WhitelistedIP.objects.get_or_create(
        ip_address=ip,
        defaults={'reason': reason, 'added_by': request.user}
    )

    if created:
        log_activity(request, 'whitelist_ip', ip, reason)
        # Remove from blocklist if currently blocked
        blocked = BlockedIP.objects.filter(ip_address=ip)
        if blocked.exists():
            blocked.delete()
            BlockedIP.sync_to_nginx()
        return JsonResponse({'status': 'whitelisted'})
    return JsonResponse({'status': 'already_whitelisted'})


@login_required
@require_http_methods(["POST"])
def remove_whitelist_ip_view(request):
    """Remove an IP from the whitelist."""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Forbidden'}, status=403)

    ip = request.POST.get('ip_address', '').strip()
    deleted, _ = WhitelistedIP.objects.filter(ip_address=ip).delete()
    if deleted:
        log_activity(request, 'remove_whitelist', ip)
        return JsonResponse({'status': 'removed'})
    return JsonResponse({'error': 'Not found'}, status=404)


@login_required
def blocked_ip_timeline_view(request):
    """Return JSON data for the 7-day rejection timeline for a specific IP."""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Forbidden'}, status=403)

    from django.utils import timezone
    from django.db.models import Count
    from django.db.models.functions import TruncHour
    from datetime import timedelta

    ip = request.GET.get('ip', '').strip()
    if not ip:
        return JsonResponse({'error': 'IP required'}, status=400)

    seven_days_ago = timezone.now() - timedelta(days=7)

    data = list(
        NginxRejection.objects.filter(
            ip_address=ip,
            timestamp__gte=seven_days_ago,
        ).annotate(
            hour=TruncHour('timestamp')
        ).values('hour').annotate(
            count=Count('id')
        ).order_by('hour').values_list('hour', 'count')
    )

    return JsonResponse({
        'ip': ip,
        'labels': [h.strftime('%m/%d %H:%M') for h, _ in data],
        'values': [c for _, c in data],
    })


@login_required
def blocklist_export_view(request):
    """Export blocked IPs as plain text, one per line."""
    if not request.user.is_superuser:
        raise PermissionDenied

    ips = BlockedIP.objects.values_list('ip_address', flat=True)
    content = '\n'.join(ips)
    response = HttpResponse(content, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="kineticlull_blocklist.txt"'
    return response


@login_required
@require_http_methods(["POST"])
def block_ip_view(request):
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Forbidden'}, status=403)

    ip = request.POST.get('ip_address', '').strip()
    reason = request.POST.get('reason', 'Manually blocked').strip()

    if not ip:
        return JsonResponse({'error': 'IP address required'}, status=400)

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return JsonResponse({'error': 'Invalid IP address'}, status=400)

    from .models import WhitelistedIP
    if WhitelistedIP.is_whitelisted(ip):
        return JsonResponse({'error': 'Cannot block a whitelisted IP'}, status=400)

    obj, created = BlockedIP.objects.get_or_create(
        ip_address=ip,
        defaults={
            'reason': reason,
            'blocked_by': request.user,
            'auto_blocked': False,
        }
    )

    if created:
        BlockedIP.sync_to_nginx()
        log_activity(request, 'ip_blocked', ip, reason)

    return JsonResponse({'status': 'blocked', 'created': created, 'ip': ip})


@login_required
@require_http_methods(["POST"])
def unblock_ip_view(request):
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Forbidden'}, status=403)

    ip = request.POST.get('ip_address', '').strip()
    if not ip:
        return JsonResponse({'error': 'IP address required'}, status=400)

    deleted, _ = BlockedIP.objects.filter(ip_address=ip).delete()
    if deleted:
        BlockedIP.sync_to_nginx()
        log_activity(request, 'ip_unblocked', ip)

    return JsonResponse({'status': 'unblocked', 'ip': ip})


def _generate_migration_script(base_dir, server_name, cert_dir, nginx_config, svc_config, python_path, ssl_mode='selfsigned', letsencrypt_email='', app_user=''):
    """Generate a self-contained bash script for Nginx migration."""
    le_email_arg = f'--email {letsencrypt_email}' if letsencrypt_email else '--register-unsafely-without-email'
    return f'''#!/bin/bash
# KineticLull - Nginx Migration Script
# Generated by the KineticLull web wizard
# Run with: sudo bash {base_dir}/deploy/migrate_to_nginx.sh

set -e

PROJECT_DIR="{base_dir}"
PROJECT_NAME="kineticlull"
CERT_DIR="{cert_dir}"
SERVER_NAME="{server_name}"
SSL_MODE="{ssl_mode}"
APP_USER="{app_user}"
SERVICE_FILE="/etc/systemd/system/${{PROJECT_NAME}}.service"
PYTHON="{python_path}"
LOGFILE="${{PROJECT_DIR}}/migration.log"

echo "Migration started at $(date)" > "${{LOGFILE}}"

log()  {{ echo -e "[*]\\t$1" | tee -a "${{LOGFILE}}"; }}
ok()   {{ echo -e "[+]\\t$1" | tee -a "${{LOGFILE}}"; }}
warn() {{ echo -e "[!]\\t$1" | tee -a "${{LOGFILE}}"; }}

# Check for root
if [ "$EUID" -ne 0 ]; then
    warn "This script must be run as root (sudo)."
    exit 1
fi

echo ""
echo "========================================="
echo "  KineticLull Nginx Migration"
echo "========================================="
echo ""

# ── Step 0: Backup ──
BACKUP_DIR="${{PROJECT_DIR}}/.migration_backup_$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"
log "Backing up current config to ${{BACKUP_DIR}}..."

if [ -f "$SERVICE_FILE" ]; then
    cp "$SERVICE_FILE" "${{BACKUP_DIR}}/kineticlull.service"
fi
if [ -f "/etc/authbind/byport/443" ]; then
    cp "/etc/authbind/byport/443" "${{BACKUP_DIR}}/authbind_443" 2>/dev/null || true
fi
ok "Backup created."

# ── Rollback function ──
rollback() {{
    warn "Rolling back..."
    if [ -f "${{BACKUP_DIR}}/kineticlull.service" ]; then
        cp "${{BACKUP_DIR}}/kineticlull.service" "$SERVICE_FILE"
    fi
    if [ -f "${{BACKUP_DIR}}/authbind_443" ]; then
        cp "${{BACKUP_DIR}}/authbind_443" "/etc/authbind/byport/443"
    fi
    rm -f "/etc/nginx/sites-enabled/${{PROJECT_NAME}}" 2>/dev/null
    rm -f "/etc/nginx/sites-available/${{PROJECT_NAME}}" 2>/dev/null
    rm -f "/etc/nginx/conf.d/${{PROJECT_NAME}}.conf" 2>/dev/null
    systemctl stop nginx 2>/dev/null || true
    systemctl daemon-reload
    systemctl restart "${{PROJECT_NAME}}" 2>/dev/null || true
    $PYTHON "${{PROJECT_DIR}}/manage.py" shell -c "
from app.models import AppSettings
s = AppSettings.load()
s.deployment_mode = 'gunicorn_ssl'
s.save()
" 2>>"${{LOGFILE}}" || true
    ok "Rollback complete. Previous config restored."
    ok "Backup at: ${{BACKUP_DIR}}"
    exit 1
}}

# ── Step 1: Install Nginx ──
log "Installing Nginx..."
if [ -f /etc/debian_version ]; then
    OS_FAMILY="debian"
    apt-get update -qq
    apt-get install -y nginx openssl 2>>"${{LOGFILE}}"
    if [ "$SSL_MODE" = "letsencrypt" ]; then
        apt-get install -y certbot python3-certbot-nginx 2>>"${{LOGFILE}}"
    fi
elif [ -f /etc/redhat-release ]; then
    OS_FAMILY="redhat"
    if command -v dnf &>/dev/null; then
        dnf install -y nginx openssl 2>>"${{LOGFILE}}"
        if [ "$SSL_MODE" = "letsencrypt" ]; then
            dnf install -y certbot python3-certbot-nginx 2>>"${{LOGFILE}}"
        fi
    else
        yum install -y nginx openssl 2>>"${{LOGFILE}}"
        if [ "$SSL_MODE" = "letsencrypt" ]; then
            yum install -y certbot python3-certbot-nginx 2>>"${{LOGFILE}}"
        fi
    fi
else
    warn "Unsupported OS."
    exit 1
fi
ok "Nginx installed."

# ── Step 2: SSL Certs ──
mkdir -p "${{CERT_DIR}}"
if [ "$SSL_MODE" = "letsencrypt" ]; then
    # Check if LE cert already exists — reuse if so.
    if [ -f "/etc/letsencrypt/live/${{SERVER_NAME}}/fullchain.pem" ]; then
        log "Let's Encrypt certificate already exists for ${{SERVER_NAME}}."
    else
        log "Requesting Let's Encrypt certificate for ${{SERVER_NAME}}..."
        # Nginx must be listening on port 80 for the HTTP-01 challenge.
        if [ -d "/etc/nginx/sites-available" ]; then
            TEMP_CONF="/etc/nginx/sites-available/${{PROJECT_NAME}}"
            cat > "$TEMP_CONF" <<TMPEOF
server {{
    listen 80;
    server_name ${{SERVER_NAME}};
    location / {{ return 200 'ok'; }}
}}
TMPEOF
            ln -sf "$TEMP_CONF" "/etc/nginx/sites-enabled/${{PROJECT_NAME}}"
            rm -f "/etc/nginx/sites-enabled/default" 2>/dev/null || true
        else
            TEMP_CONF="/etc/nginx/conf.d/${{PROJECT_NAME}}.conf"
            cat > "$TEMP_CONF" <<TMPEOF
server {{
    listen 80;
    server_name ${{SERVER_NAME}};
    location / {{ return 200 'ok'; }}
}}
TMPEOF
        fi
        nginx -t 2>>"${{LOGFILE}}" || rollback
        systemctl enable nginx 2>>"${{LOGFILE}}"
        systemctl restart nginx

        LE_SUCCESS=false
        for attempt in 1 2; do
            if certbot certonly --nginx -d "${{SERVER_NAME}}" --non-interactive --agree-tos \\
                {le_email_arg} 2>>"${{LOGFILE}}"; then
                LE_SUCCESS=true
                break
            fi
            [ "$attempt" -eq 1 ] && {{ log "Retrying certbot in 5s..."; sleep 5; }}
        done

        if [ "$LE_SUCCESS" = false ]; then
            warn "Let's Encrypt failed. Check DNS points to this server and ports 80/443 are reachable."
            warn "See ${{LOGFILE}} for details."
            rollback
        fi
        ok "Let's Encrypt certificate issued."
    fi

    # Symlink LE certs into CERT_DIR so the nginx config paths are stable.
    ln -sf "/etc/letsencrypt/live/${{SERVER_NAME}}/fullchain.pem" "${{CERT_DIR}}/cert.pem"
    ln -sf "/etc/letsencrypt/live/${{SERVER_NAME}}/privkey.pem" "${{CERT_DIR}}/key.pem"

    # Enable auto-renewal.
    if systemctl list-unit-files 2>/dev/null | grep -q certbot.timer; then
        systemctl enable certbot.timer 2>>"${{LOGFILE}}"
        systemctl start certbot.timer 2>>"${{LOGFILE}}"
        ok "Certbot auto-renewal timer enabled."
    else
        (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --deploy-hook 'systemctl reload nginx'") | crontab -
        ok "Certbot renewal cron job added (daily at 3am)."
    fi
elif [ -f "${{CERT_DIR}}/cert.pem" ] && [ -f "${{CERT_DIR}}/key.pem" ]; then
    log "SSL certs already exist."
elif [ -f "${{PROJECT_DIR}}/cert.pem" ] && [ -f "${{PROJECT_DIR}}/key.pem" ]; then
    log "Moving certs from project root..."
    cp "${{PROJECT_DIR}}/cert.pem" "${{CERT_DIR}}/cert.pem"
    cp "${{PROJECT_DIR}}/key.pem" "${{CERT_DIR}}/key.pem"
    chmod 600 "${{CERT_DIR}}/key.pem"
    chmod 644 "${{CERT_DIR}}/cert.pem"
    ok "Certs moved."
else
    log "Generating self-signed SSL certificate..."
    openssl req -x509 -newkey rsa:4096 \\
        -keyout "${{CERT_DIR}}/key.pem" \\
        -out "${{CERT_DIR}}/cert.pem" \\
        -days 1825 -nodes \\
        -subj "/CN={server_name}/O=KineticLull/OU=Self-Signed" \\
        2>>"${{LOGFILE}}"
    chmod 600 "${{CERT_DIR}}/key.pem"
    chmod 644 "${{CERT_DIR}}/cert.pem"
    ok "SSL cert generated."
fi

# ── Step 3: Write Nginx config ──
log "Writing Nginx configuration..."
if [ -f /etc/debian_version ]; then
    cat > "/etc/nginx/sites-available/${{PROJECT_NAME}}" << 'NGINXEOF'
{nginx_config}
NGINXEOF
    ln -sf "/etc/nginx/sites-available/${{PROJECT_NAME}}" "/etc/nginx/sites-enabled/${{PROJECT_NAME}}"
    rm -f "/etc/nginx/sites-enabled/default" 2>/dev/null || true
else
    cat > "/etc/nginx/conf.d/${{PROJECT_NAME}}.conf" << 'NGINXEOF'
{nginx_config}
NGINXEOF
fi

# Ensure Nginx can traverse the path to staticfiles
log "Setting directory permissions for Nginx traversal..."
TRAV_DIR="${{PROJECT_DIR}}"
while [ "$TRAV_DIR" != "/" ]; do
    chmod o+x "$TRAV_DIR"
    TRAV_DIR=$(dirname "$TRAV_DIR")
done

# ── Step 4: Test Nginx config ──
if ! nginx -t 2>>"${{LOGFILE}}"; then
    warn "Nginx config test failed."
    rollback
fi
ok "Nginx config tested OK."

# ── Step 5: Update systemd service ──
log "Updating Gunicorn systemd service..."
cat > "$SERVICE_FILE" << 'SVCEOF'
{svc_config}
SVCEOF
ok "Systemd service updated."

# ── Step 5.5: Grant app user read access to nginx access log (for rejection counter) ──
if [ -n "$APP_USER" ] && getent group adm >/dev/null 2>&1; then
    if id -nG "$APP_USER" 2>/dev/null | tr ' ' '\\n' | grep -qx adm; then
        log "App user $APP_USER already in adm group."
    else
        log "Adding $APP_USER to adm group for nginx log access..."
        usermod -aG adm "$APP_USER" 2>>"${{LOGFILE}}" || warn "Could not add $APP_USER to adm — rejection counter may not populate."
    fi
fi

# ── Step 6: Restart services ──
log "Restarting services..."
systemctl daemon-reload
systemctl restart "${{PROJECT_NAME}}"
systemctl enable nginx 2>>"${{LOGFILE}}"
systemctl restart nginx

# ── Step 7: Health check ──
sleep 2
HTTP_CODE=$(curl -sk -o /dev/null -w '%{{http_code}}' "https://localhost/" 2>/dev/null || echo "000")

if [ "${{HTTP_CODE}}" != "200" ] && [ "${{HTTP_CODE}}" != "302" ]; then
    warn "Health check failed (HTTP ${{HTTP_CODE}})."
    rollback
fi
ok "Health check passed (HTTP ${{HTTP_CODE}})."

# ── Step 8: Update AppSettings ──
$PYTHON "${{PROJECT_DIR}}/manage.py" shell -c "
from app.models import AppSettings
s = AppSettings.load()
s.deployment_mode = 'nginx_gunicorn'
s.save()
" 2>>"${{LOGFILE}}"
ok "AppSettings updated."

# ── Step 9: Cleanup ──
if [ -f "/etc/authbind/byport/443" ]; then
    rm -f "/etc/authbind/byport/443"
    log "Removed legacy authbind config."
fi

# Firewall
if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-service=https 2>/dev/null || true
    firewall-cmd --permanent --add-service=http 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
elif command -v ufw &>/dev/null; then
    ufw allow 'Nginx Full' 2>/dev/null || true
fi

echo ""
echo "========================================="
ok "Migration to Nginx + Gunicorn complete!"
ok "KineticLull is running at https://{server_name}"
ok "Backup saved at: ${{BACKUP_DIR}}"
echo "========================================="
'''

# @login_required
# def script_list(request):
#     script_list = Script.objects.all()
#     # print(script_list.name)
#     return render(request, 'script_list.html', {'script_list' : script_list},)

# @login_required
# def review_script(request, script_id):
#     script = get_object_or_404(Script, id=script_id)
#     is_creator = request.user == script.creator
    
#     if request.method == "POST":
#         form = ScriptForm(request.POST, instance=script)
#         if form.is_valid():
#             form.save()
#             return redirect('app:script_list')
#     else:
#         form = ScriptForm(instance=script)
#         if is_creator:
#             # Exclude the 'is_approved' field for the creator of the script
#             # Can't self-approve your own scripts
#             form.fields.pop('is_approved')

#     context = {
#         'form': form
#         }
#     return render(request, 'review_script.html', context)

# @login_required
# def approve_script(request, script_id):
#     script = get_object_or_404(Script, id=script_id)
#     if request.user != script.creator and request.user.has_perm('app.can_approve_script'):
#         script.is_approved = True
#         script.save()
#         # Redirect to the review page or display success message
#         return redirect('script_review')
#     else:
#         raise PermissionDenied


# ── URL Shortener ──────────────────────────────────────────────

@login_required
def short_urls_view(request):
    """List the current user's shortened URLs."""
    app_settings = AppSettings.load()
    urls = ShortenedURL.objects.filter(created_by=request.user)
    per_page = request.GET.get("per_page", "25")
    try:
        per_page = max(1, min(int(per_page), 100))
    except (ValueError, TypeError):
        per_page = 25
    paginator = Paginator(urls, per_page)
    page_obj = paginator.get_page(request.GET.get("page"))

    base_url = settings.KINETICLULL_URL if hasattr(settings, 'KINETICLULL_URL') else os.environ.get('KINETICLULL_URL', 'http://127.0.0.1:8000')
    for url in page_obj:
        url.short_url = f"{base_url}/s/{url.short_code}"

    context = {
        'page_obj': page_obj,
        'per_page': per_page,
    }
    summary = get_security_summary(request.user)
    if summary:
        context['security_summary'] = summary
    return render(request, 'short_urls.html', context)


@login_required
def create_short_url(request):
    """Create a new shortened URL via a dedicated form page."""
    if request.method == 'POST':
        form = ShortenedURLForm(request.POST)
        if form.is_valid():
            short_url = form.save(commit=False)
            short_url.created_by = request.user
            short_url.save()
            log_activity(request, 'create_short_url', short_url.short_code, short_url.original_url)
            messages.success(request, f'Short URL created: /s/{short_url.short_code}')
            return redirect('app:short_urls')
    else:
        form = ShortenedURLForm()
    return render(request, 'edit_short_url.html', {'form': form})


@login_required
def edit_short_url(request, url_id):
    """Edit an existing shortened URL owned by the current user."""
    short_url = get_object_or_404(ShortenedURL, id=url_id, created_by=request.user)
    if request.method == 'POST':
        form = ShortenedURLForm(request.POST, instance=short_url)
        if form.is_valid():
            form.save()
            log_activity(request, 'edit_short_url', short_url.short_code, short_url.original_url)
            messages.success(request, 'Short URL updated.')
            return redirect('app:short_urls')
    else:
        form = ShortenedURLForm(instance=short_url)
    return render(request, 'edit_short_url.html', {'form': form, 'short_url': short_url})


@login_required
def delete_short_url(request, url_id):
    """Delete a shortened URL owned by the current user."""
    short_url = get_object_or_404(ShortenedURL, id=url_id, created_by=request.user)
    code = short_url.short_code
    short_url.delete()
    log_activity(request, 'delete_short_url', code)
    messages.success(request, 'Short URL deleted.')
    return redirect('app:short_urls')


def redirect_short_url(request, short_code):
    """Public redirect endpoint — no login required."""
    short_url = get_object_or_404(ShortenedURL, short_code=short_code)
    ShortenedURL.objects.filter(pk=short_url.pk).update(hit_count=models.F('hit_count') + 1)
    return HttpResponseRedirect(short_url.original_url)


# ── One-Time File Sharing ──────────────────────────────────────

@login_required
def otf_list_view(request):
    """List the current user's active (unburned, unexpired) one-time files."""
    files = OneTimeFile.objects.filter(uploaded_by=request.user, burned=False, downloaded=False)
    # Filter out expired ones in Python to also trigger cleanup
    from django.utils import timezone as tz
    active_files = []
    for f in files:
        if f.is_expired:
            f.burn()
        else:
            active_files.append(f)

    base_url = settings.KINETICLULL_URL if hasattr(settings, 'KINETICLULL_URL') else os.environ.get('KINETICLULL_URL', 'http://127.0.0.1:8000')
    for f in active_files:
        f.share_url = f'{base_url}/f/{f.token}/'

    context = {'files': active_files}
    summary = get_security_summary(request.user)
    if summary:
        context['security_summary'] = summary
    return render(request, 'otf_list.html', context)


@login_required
def otf_upload_view(request):
    """Upload a file for one-time sharing."""
    app_settings = AppSettings.load()

    if not app_settings.resend_api_key or not app_settings.resend_from_email:
        messages.error(request, 'Email is not configured. Set up Resend API key and From email in Settings before sharing files.')
        return redirect('app:otf_list')

    if request.method == 'POST':
        uploaded_file = request.FILES.get('file')
        recipient_email = request.POST.get('recipient_email', '').strip()
        expiry_hours = request.POST.get('expiry_hours', '24')

        if not uploaded_file or not recipient_email:
            messages.error(request, 'File and recipient email are required.')
            return render(request, 'otf_upload.html', {'expiry_choices': OneTimeFile.EXPIRY_CHOICES})

        # Check file size
        max_size = app_settings.max_file_size_mb * 1024 * 1024
        if uploaded_file.size > max_size:
            messages.error(request, f'File exceeds the {app_settings.max_file_size_mb}MB limit.')
            return render(request, 'otf_upload.html', {'expiry_choices': OneTimeFile.EXPIRY_CHOICES})

        try:
            expiry_hours = int(expiry_hours)
        except ValueError:
            expiry_hours = 24

        otf = OneTimeFile(
            file=uploaded_file,
            original_filename=uploaded_file.name,
            uploaded_by=request.user,
            recipient_email=recipient_email,
            expiry_hours=expiry_hours,
        )
        otf.save()

        base_url = settings.KINETICLULL_URL if hasattr(settings, 'KINETICLULL_URL') else os.environ.get('KINETICLULL_URL', 'http://127.0.0.1:8000')
        share_url = f'{base_url}/f/{otf.token}/'

        sender_name = f'{request.user.first_name} {request.user.last_name}'.strip() or request.user.email
        sent = send_file_shared_email(recipient_email, otf.original_filename, share_url, sender_name)

        log_activity(request, 'upload_otf', otf.original_filename, f'To: {recipient_email}, Expires: {expiry_hours}h')
        if sent:
            messages.success(request, f'File shared and notification sent to {recipient_email}.')
        else:
            messages.warning(request, f'File shared but email failed to send. Share this link manually: {share_url}')
        return redirect('app:otf_list')

    return render(request, 'otf_upload.html', {'expiry_choices': OneTimeFile.EXPIRY_CHOICES})


@login_required
def otf_brand_preview(request):
    """Preview the branded download page."""
    if not request.user.is_superuser:
        raise PermissionDenied
    return render(request, 'otf_verify.html', {'token': 'preview', 'preview_mode': True})


@login_required
@require_http_methods(["POST"])
def otf_delete_view(request, token):
    """Delete a one-time file and burn the link."""
    otf = get_object_or_404(OneTimeFile, token=token, uploaded_by=request.user)
    filename = otf.original_filename
    otf.burn()
    log_activity(request, 'delete_otf', filename)
    return JsonResponse({'status': 'deleted'})


def otf_download_view(request, token):
    """Public download endpoint — handles OTP verification and file delivery."""
    otf = get_object_or_404(OneTimeFile, token=token)

    # Check if burned or expired
    if otf.burned or otf.downloaded:
        return render(request, 'otf_burned.html')

    if otf.is_expired:
        otf.burn()
        return render(request, 'otf_burned.html')

    # Step 1: First visit — send OTP
    if request.method == 'GET' and not request.GET.get('verify'):
        otp = otf.generate_otp()
        sent = send_otp_email(otf.recipient_email, otp)
        if not sent:
            return render(request, 'otf_error.html', {'message': 'Failed to send verification email. Contact the sender.'})
        log_activity(request, 'otf_accessed', otf.original_filename, f'OTP sent to {otf.recipient_email}')
        return render(request, 'otf_verify.html', {'token': token})

    # Step 2: OTP verification
    if request.method == 'POST':
        code = request.POST.get('otp', '').strip()
        if otf.verify_otp(code):
            # Serve the file
            from django.utils import timezone as tz
            otf.downloaded = True
            otf.downloaded_at = tz.now()
            otf.save()

            # Notify uploader
            if otf.uploaded_by:
                send_access_notification(otf.uploaded_by.email, otf.recipient_email, otf.original_filename)

            log_activity(request, 'otf_downloaded', otf.original_filename, f'By: {otf.recipient_email}')

            # Serve file then burn
            response = HttpResponse(otf.file.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{otf.original_filename}"'

            # Burn after serving
            otf.burn()

            return response
        else:
            messages.error(request, 'Invalid or expired code. A new code has been sent.')
            otp = otf.generate_otp()
            send_otp_email(otf.recipient_email, otp)
            return render(request, 'otf_verify.html', {'token': token})
