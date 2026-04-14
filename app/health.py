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

from django.conf import settings


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


def _resolve_cert_path():
    """Find the actual SSL cert file by parsing the active nginx config, with project ssl/ as fallback."""
    import re
    for conf in ('/etc/nginx/sites-enabled/kineticlull',
                 '/etc/nginx/sites-available/kineticlull',
                 '/etc/nginx/conf.d/kineticlull.conf'):
        try:
            with open(conf) as f:
                text = f.read()
        except (FileNotFoundError, PermissionError):
            continue
        m = re.search(r'^\s*ssl_certificate\s+([^;]+);', text, re.MULTILINE)
        if m:
            path = m.group(1).strip()
            # Resolve symlinks and return the real path if it exists.
            if os.path.exists(path):
                return path, conf
    # Fallback: legacy gunicorn_ssl mode uses <project>/ssl/cert.pem directly
    fallback = os.path.join(settings.BASE_DIR, 'ssl', 'cert.pem')
    if os.path.exists(fallback):
        return fallback, 'ssl/cert.pem'
    return None, None


def check_ssl_cert():
    cert_path, source = _resolve_cert_path()
    if not cert_path:
        return _check(
            'ssl_cert', 'SSL certificate', True, 'info',
            'No cert found. Nginx may not be configured with SSL on this install.',
        )
    try:
        r = subprocess.run(
            ['openssl', 'x509', '-in', cert_path, '-noout', '-enddate'],
            capture_output=True, text=True, timeout=3,
        )
        if r.returncode != 0:
            raise RuntimeError((r.stderr or '').strip())
        line = r.stdout.strip()
        if '=' not in line:
            raise ValueError(f'unexpected openssl output: {line!r}')
        date_str = line.split('=', 1)[1]
        expiry = datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry - datetime.utcnow()).days
    except FileNotFoundError:
        return _check(
            'ssl_cert', 'SSL certificate', False, 'warning',
            'openssl binary not found — cannot check cert expiry.',
            fix_commands=['sudo apt-get install -y openssl  # Debian/Ubuntu',
                          'sudo dnf install -y openssl  # RHEL/Fedora'],
        )
    except Exception as e:
        return _check('ssl_cert', 'SSL certificate', False, 'warning',
                      f'Could not parse cert expiry: {e}')

    path_note = f' Using {cert_path}.'
    if days_left < 0:
        return _check(
            'ssl_cert', 'SSL certificate', False, 'error',
            f'Expired {-days_left} days ago.' + path_note,
            why='Browsers reject the connection. If HSTS is enabled the site is effectively unreachable until renewed.',
            fix_commands=[
                'sudo certbot renew  # Let\'s Encrypt',
                '# Self-signed: re-run the Nginx migration wizard to regenerate',
            ],
        )
    if days_left < 7:
        return _check(
            'ssl_cert', 'SSL certificate', False, 'warning',
            f'Expires in {days_left} days.' + path_note,
            fix_commands=['sudo certbot renew'],
        )
    return _check('ssl_cert', 'SSL certificate', True, 'ok', f'Valid ({days_left} days remaining).' + path_note)


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


FIXES = {
    'nginx_log_add_user': _fix_nginx_log_add_user,
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
