"""
System health checks. Each check returns a dict describing the condition and,
when the app can't auto-remediate, the exact CLI command(s) the operator should
run. Some fixes are wired to an allowlisted server-side executor (see FIXES
below) so the UI can offer a "Run Fix" button.

Design rule: never hide a CLI intervention. If the app depends on something
outside its control, surface it here.
"""

import getpass
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path

from django.conf import settings


# Captured at app.ready() — see app/apps.py. Used to detect when code on disk
# diverges from what the running workers imported (stale workers after a pull).
BOOT_VERSION = None
BOOT_TIME = None


def _current_version():
    try:
        return (Path(settings.BASE_DIR) / 'VERSION').read_text().strip()
    except Exception:
        return 'unknown'


def set_boot_snapshot():
    global BOOT_VERSION, BOOT_TIME
    BOOT_VERSION = _current_version()
    BOOT_TIME = time.time()


_cache = {'results': None, 'ts': 0.0}
_CACHE_SECONDS = 60


def _app_user():
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get('USER', 'kineticlull')


def _check(id, name, ok, severity, message, why='', fix_commands=None, runnable_fix_id=None, post_fix_note=''):
    return {
        'id': id,
        'name': name,
        'ok': ok,
        'severity': severity,
        'message': message,
        'why': why,
        'fix_commands': fix_commands or [],
        'runnable_fix_id': runnable_fix_id,
        'post_fix_note': post_fix_note,
    }


def check_nginx_log_readable():
    path = '/var/log/nginx/access.log'
    if not os.path.exists(path):
        return _check(
            'nginx_log', 'Nginx access log', True, 'info',
            'Log not present yet (Nginx may not be running or this install is pre-Nginx).',
        )
    if os.access(path, os.R_OK):
        return _check('nginx_log', 'Nginx access log', True, 'ok', 'Readable by the app.')
    user = _app_user()
    return _check(
        'nginx_log', 'Nginx access log', False, 'error',
        f'App user ({user}) cannot read {path}.',
        why='The rejection counter on the Blocked IPs page populates from this log. Without read access it stays at 0.',
        fix_commands=[
            f'sudo usermod -aG adm {user}',
            'sudo systemctl restart kineticlull',
        ],
        runnable_fix_id='nginx_log_add_user',
        post_fix_note='Group change applied. The service was restarted — the rejection counter will begin populating within 5 minutes.',
    )


def check_cryptography():
    try:
        import cryptography  # noqa: F401
        return _check('cryptography', 'Encryption library', True, 'ok', 'Installed.')
    except ImportError:
        return _check(
            'cryptography', 'Encryption library', False, 'error',
            'The cryptography package is not installed.',
            why='Required for at-rest encryption of secrets (Resend API key, future B2 keys). Migrations that import app.crypto will fail.',
            fix_commands=[
                'source venv/bin/activate && pip install -r requirements.txt',
                'sudo systemctl restart kineticlull',
            ],
        )


def check_sudoers():
    try:
        r = subprocess.run(['sudo', '-n', 'nginx', '-t'], capture_output=True, timeout=3)
        if r.returncode == 0:
            return _check('sudoers', 'Sudoers rules', True, 'ok', 'Configured.')
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return _check(
        'sudoers', 'Sudoers rules', False, 'warning',
        'Web UI cannot manage Nginx or restart services without passwordless sudo entries.',
        why='Features like blocklist reloads, service restarts, and cert rotation silently fail from the UI without these rules.',
        fix_commands=['bash upgrade.sh'],
    )


def check_ssl_cert():
    """Check the cert nginx is actually serving by opening a TLS connection to 127.0.0.1:443.

    Reads the cert from the live handshake — no filesystem access needed, no
    permission changes required, works for every cert type (LE, self-signed,
    symlinked, etc.). Also catches the case where the config path doesn't
    match what's actually being served.
    """
    import socket
    import ssl as ssl_mod
    from urllib.parse import urlparse

    url = getattr(settings, 'KINETICLULL_URL', os.environ.get('KINETICLULL_URL', ''))
    hostname = (urlparse(url).hostname if url else None) or 'localhost'

    try:
        ctx = ssl_mod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_mod.CERT_NONE
        with socket.create_connection(('127.0.0.1', 443), timeout=3) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                der = tls.getpeercert(binary_form=True)
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return _check(
            'ssl_cert', 'SSL certificate', True, 'info',
            f'Could not reach 127.0.0.1:443 ({type(e).__name__}). Nginx may not be configured with SSL on this install.',
        )

    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        expiry = cert.not_valid_after_utc
        now = datetime.now(tz=expiry.tzinfo)
        days_left = (expiry - now).days
        issuer_cn = ''
        for attr in cert.issuer:
            if attr.oid._name == 'commonName':
                issuer_cn = attr.value
                break
    except Exception as e:
        return _check('ssl_cert', 'SSL certificate', False, 'warning',
                      f'Could not parse served cert: {e}')

    issuer_note = f' Issuer: {issuer_cn}.' if issuer_cn else ''
    if days_left < 0:
        return _check(
            'ssl_cert', 'SSL certificate', False, 'error',
            f'Expired {-days_left} days ago.' + issuer_note,
            why='Browsers reject the connection. If HSTS is enabled the site is effectively unreachable until renewed.',
            fix_commands=[
                'sudo certbot renew  # Let\'s Encrypt',
                '# Self-signed: re-run the Nginx migration wizard to regenerate',
            ],
        )
    if days_left < 7:
        return _check(
            'ssl_cert', 'SSL certificate', False, 'warning',
            f'Expires in {days_left} days.' + issuer_note,
            fix_commands=['sudo certbot renew'],
        )
    return _check('ssl_cert', 'SSL certificate', True, 'ok', f'Valid ({days_left} days remaining).' + issuer_note)


def check_code_stale():
    """Detect when code on disk is newer than what the running workers imported."""
    if BOOT_VERSION is None:
        return _check('code_stale', 'Running code', True, 'info', 'Boot snapshot not yet recorded.')
    current = _current_version()
    if current == BOOT_VERSION:
        return _check('code_stale', 'Running code', True, 'ok', f'Workers running {current}.')
    return _check(
        'code_stale', 'Running code', False, 'error',
        f'Workers running {BOOT_VERSION} but {current} is on disk.',
        why='The code was updated after the last restart. Workers are still serving old Python. Restart required for the new code to take effect.',
        fix_commands=['sudo systemctl restart kineticlull'],
        runnable_fix_id='restart_kineticlull',
        post_fix_note='Service restarted. The new code is now live. Your browser session will reconnect.',
    )


def check_version_up_to_date():
    """Flag when the installed VERSION doesn't match origin/main's VERSION."""
    from .views import get_current_version, get_remote_version
    try:
        current = get_current_version()
        latest = get_remote_version()
    except Exception:
        return _check('version', 'Version', True, 'info', 'Could not determine version state.')
    if not latest:
        return _check('version', 'Version', True, 'info', f'Version {current} — could not reach origin to check for updates.')
    if current == latest:
        return _check('version', 'Version', True, 'ok', f'Up to date ({current}).')
    return _check(
        'version', 'Version', False, 'warning',
        f'Installed: {current} — available: {latest}.',
        why='The code on disk is behind origin/main. Fixes and features you see in documentation or screenshots will not appear until you upgrade.',
        fix_commands=[
            'bash upgrade.sh  # CLI path',
            '# Or: open the Upgrade page in the web UI and click Upgrade Now',
        ],
    )


CHECKS = [
    check_code_stale,
    check_version_up_to_date,
    check_nginx_log_readable,
    check_cryptography,
    check_sudoers,
    check_ssl_cert,
]


def run_all(force=False):
    now = time.time()
    if not force and _cache['results'] and (now - _cache['ts']) < _CACHE_SECONDS:
        return _cache['results']
    results = []
    for fn in CHECKS:
        try:
            results.append(fn())
        except Exception as e:
            results.append(_check(fn.__name__, fn.__name__, False, 'warning', f'check errored: {e}'))
    _cache['results'] = results
    _cache['ts'] = now
    return results


def count_issues():
    return sum(1 for c in run_all() if not c['ok'])


# ─── Allowlisted fixes ──────────────────────────────────────────────────────
# Keys are referenced by `runnable_fix_id` on individual checks. Values are
# callables that return (ok, stdout_text). Never accept arbitrary user input
# into subprocess arguments — only lookups into this dict.

def _fix_nginx_log_add_user():
    """Add the app user to the adm group so nginx access log is readable, then restart the service."""
    user = _app_user()
    try:
        r1 = subprocess.run(
            ['sudo', '-n', '/usr/sbin/usermod', '-aG', 'adm', user],
            capture_output=True, text=True, timeout=10,
        )
        if r1.returncode != 0:
            return False, (
                f'usermod failed (rc={r1.returncode}). '
                f'This usually means the sudoers entry is missing. '
                f'Run `bash upgrade.sh` on the server to install it.\n\n'
                f'stderr:\n{r1.stderr.strip()}'
            )
        r2 = subprocess.run(
            ['sudo', '-n', '/usr/bin/systemctl', 'restart', 'kineticlull'],
            capture_output=True, text=True, timeout=15,
        )
        output = f'Added {user} to adm group.\n{r2.stdout}\n{r2.stderr}'.strip()
        return r2.returncode == 0, output
    except FileNotFoundError as e:
        return False, f'Required binary not found: {e}'
    except subprocess.TimeoutExpired:
        return False, 'Command timed out.'


def _fix_restart_kineticlull():
    """Trigger a full restart of kineticlull + nginx via the cgroup-escaping helper.

    The helper (installed by upgrade.sh) uses systemd-run to launch the restart
    in a new transient unit, so it survives systemd killing our own cgroup.
    """
    try:
        r = subprocess.run(
            ['sudo', '-n', '/usr/local/bin/kl-restart'],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            return True, 'Restart triggered. Page will reconnect in a few seconds.'
        stderr = (r.stderr or '').strip()
        return False, (
            f'Restart helper failed (rc={r.returncode}).\n\n'
            f'Most likely the helper isn\'t installed yet — run `bash upgrade.sh` once on the server '
            f'to install /usr/local/bin/kl-restart and the matching sudoers entry.\n\n'
            f'stderr:\n{stderr}'
        )
    except FileNotFoundError:
        return False, 'sudo not found on PATH.'
    except subprocess.TimeoutExpired:
        return False, 'Restart helper timed out.'


FIXES = {
    'nginx_log_add_user': _fix_nginx_log_add_user,
    'restart_kineticlull': _fix_restart_kineticlull,
}


def run_fix(fix_id):
    """Execute an allowlisted fix. Returns (ok, output_str)."""
    fn = FIXES.get(fix_id)
    if fn is None:
        return False, f'Unknown fix id: {fix_id}'
    ok, output = fn()
    # Bust the cache so the health page reflects the new state on next render
    _cache['results'] = None
    _cache['ts'] = 0.0
    return ok, output
