from django.apps import AppConfig


class EdlConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app'

    def ready(self):
        from django.db.models.signals import post_migrate
        post_migrate.connect(ensure_superuser_group, sender=self)
        from . import signals  # noqa: F401 — registers auth signal receivers
        from . import health
        health.set_boot_snapshot()

        # Empty-file fallback runs in every process. nginx -t fails fast if
        # deploy/blocklist.conf is missing (it's git-ignored and a fresh clone
        # won't have it), so we can't gate this behind the leader lock.
        _ensure_blocklist_file_exists()

        # Everything below runs in exactly one process per host. Gating these
        # one-shot startup tasks avoids races like the one that produced
        # duplicate system EDL rows under default --workers 3.
        if _is_startup_leader():
            _patch_nginx_config()
            _sync_blocklist_from_db()
            _start_scheduler_threads()


def _ensure_blocklist_file_exists():
    """Create deploy/blocklist.conf as an empty file if missing.

    nginx `include`s this file and refuses to start when it's absent. The file
    is git-ignored (operator state, varies per install) so a pull or fresh
    clone won't have it. Idempotent and safe to run from every worker — pure
    filesystem, no DB.
    """
    import os
    from django.conf import settings

    blocklist_path = os.path.join(settings.BASE_DIR, 'deploy', 'blocklist.conf')
    try:
        os.makedirs(os.path.dirname(blocklist_path), exist_ok=True)
        if not os.path.exists(blocklist_path):
            with open(blocklist_path, 'w'):
                pass  # empty file is a valid nginx include target
    except Exception:
        pass


def _sync_blocklist_from_db():
    """Rewrite deploy/blocklist.conf from BlockedIP rows and sync the system EDL.

    Leader-only: BlockedIP.sync_to_nginx() also calls
    ExtDynLists.sync_system_blocklist(), and concurrent get_or_create across
    workers can produce duplicate system EDL rows. The DB constraint catches
    that, but gating it here means the constraint never has to fire in
    healthy operation.
    """
    try:
        from app.models import BlockedIP
        BlockedIP.sync_to_nginx()
    except Exception:
        pass  # DB may not be ready (e.g., mid-migration); empty file is enough


_startup_leader_fd = None  # keep the lock fd alive for the process lifetime


def _is_startup_leader():
    """Return True if this process should run one-shot startup tasks.

    Two gates:
      1. We're under gunicorn or `runserver` — not a `manage.py migrate` /
         `collectstatic` / shell, where startup work would either crash on a
         not-ready DB or run pointlessly.
      2. We won the fcntl flock on backups/.startup.lock — exactly one
         process per host can hold it. Other workers see EWOULDBLOCK and
         return False. The kernel releases the lock when the holder dies, so
         a worker restart re-elects automatically.
    """
    global _startup_leader_fd
    if _startup_leader_fd is not None:
        return True  # already elected in this process

    import os

    # Gate 1: only under a long-lived web process.
    is_runserver = os.environ.get('RUN_MAIN') == 'true'
    is_gunicorn = (
        'gunicorn' in os.environ.get('SERVER_SOFTWARE', '')
        or 'gunicorn' in (os.environ.get('_', '') or '')
    )
    if not (is_runserver or is_gunicorn):
        return False

    # Gate 2: fcntl flock — only one worker wins.
    import fcntl
    from django.conf import settings

    lock_path = os.path.join(settings.BASE_DIR, 'backups', '.startup.lock')
    fd = None
    try:
        os.makedirs(os.path.dirname(lock_path), exist_ok=True)
        fd = open(lock_path, 'w')
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        if fd is not None:
            try:
                fd.close()
            except Exception:
                pass
        return False

    _startup_leader_fd = fd  # keep alive for process lifetime; kernel cleans up on exit
    return True


def _start_scheduler_threads():
    """Spawn the daily-backup, cleanup, and rejection-parser background threads.

    Caller must already have confirmed leader status — this function does not
    re-check, it just spawns. Each thread has its own startup grace period
    and internal scheduling.
    """
    import threading
    import time

    def _backup_loop():
        """Run the daily backup at the configured local time-of-day.

        Computes the next run target each pass and sleeps up to 1 hour at a
        time so changes to the configured time take effect within the hour.

        On restart we *do not* catch up missed runs. If the service was down
        at the scheduled time today, skip until tomorrow's target. A backup
        taken right after a restart captures post-restart state and provides
        no real recovery value (and would let restart loops bloat disk + B2
        with redundant tarballs of the same state).
        """
        from datetime import datetime, time as dtime, timedelta
        try:
            from zoneinfo import ZoneInfo
        except ImportError:
            ZoneInfo = None

        time.sleep(60)  # startup grace

        # Initialize last_run_date so the loop only fires at the scheduled time:
        #   - If today's target has already passed when we boot, mark today done.
        #     The loop will sleep until tomorrow's target.
        #   - If we boot before today's target, leave None so the loop fires
        #     when it naturally crosses the target.
        last_run_date = None
        try:
            from app.models import AppSettings
            app_settings = AppSettings.objects.filter(pk=1).first()
            target = (app_settings.backup_time if app_settings and app_settings.backup_time else dtime(2, 0))
            tz_name = app_settings.timezone if app_settings else 'UTC'
            tz = ZoneInfo(tz_name) if ZoneInfo else None
            now_local = datetime.now(tz=tz)
            today_target = now_local.replace(hour=target.hour, minute=target.minute, second=0, microsecond=0)
            if now_local >= today_target:
                last_run_date = now_local.date()
        except Exception:
            pass

        while True:
            sleep_secs = 3600
            try:
                from app.models import AppSettings
                from django.core.management import call_command

                app_settings = AppSettings.objects.filter(pk=1).first()
                target = (app_settings.backup_time if app_settings and app_settings.backup_time else dtime(2, 0))
                tz_name = app_settings.timezone if app_settings else 'UTC'
                tz = ZoneInfo(tz_name) if ZoneInfo else None

                now_local = datetime.now(tz=tz)
                today_target = now_local.replace(hour=target.hour, minute=target.minute, second=0, microsecond=0)

                if now_local >= today_target and last_run_date != now_local.date():
                    call_command('backup_data')
                    _maybe_upload_to_b2()
                    last_run_date = now_local.date()
                else:
                    next_target = today_target if now_local < today_target else today_target + timedelta(days=1)
                    delta = (next_target - now_local).total_seconds()
                    sleep_secs = max(60, min(delta, 3600))
            except Exception:
                pass
            time.sleep(sleep_secs)

    def _cleanup_loop():
        """Burn expired one-time files every 5 minutes."""
        time.sleep(120)
        while True:
            try:
                from app.models import OneTimeFile
                from django.utils import timezone
                expired = OneTimeFile.objects.filter(burned=False, expires_at__lte=timezone.now())
                for otf in expired:
                    otf.burn()
            except Exception:
                pass
            time.sleep(300)

    def _rejection_parser_loop():
        """Parse nginx access log for 403s every 5 minutes."""
        time.sleep(30)
        while True:
            try:
                from django.core.management import call_command
                call_command('parse_nginx_rejections')
            except Exception:
                pass
            time.sleep(300)

    t = threading.Thread(target=_backup_loop, daemon=True)
    t.start()
    t2 = threading.Thread(target=_cleanup_loop, daemon=True)
    t2.start()
    t3 = threading.Thread(target=_rejection_parser_loop, daemon=True)
    t3.start()


def _maybe_upload_to_b2():
    """If B2 backup is configured, push the latest local tarball offsite."""
    from django.conf import settings
    from app.models import AppSettings
    from app import b2_backup

    app_settings = AppSettings.objects.filter(pk=1).first()
    if not app_settings or not app_settings.b2_enabled:
        return
    latest = b2_backup.latest_backup_path(settings.BASE_DIR)
    if not latest:
        return
    b2_backup.upload_file(latest, app_settings)
    app_settings.save()


def _patch_nginx_config():
    """Patch Nginx config on startup if needed, adds media/branding and client_max_body_size.

    Leader-only: caller must already have confirmed leader status. Multiple
    workers running `sudo sed -i` against the same file at the same time is a
    great way to corrupt it.
    """
    import subprocess
    import os
    from django.conf import settings

    nginx_conf = None
    for path_candidate in [
        '/etc/nginx/sites-available/kineticlull',
        '/etc/nginx/conf.d/kineticlull.conf',
    ]:
        if os.path.exists(path_candidate):
            nginx_conf = path_candidate
            break

    if not nginx_conf:
        return

    try:
        with open(nginx_conf, 'r') as f:
            content = f.read()

        changed = False
        base_dir = str(settings.BASE_DIR)

        if 'client_max_body_size' not in content:
            subprocess.run(
                ['sudo', '-n', 'sed', '-i', '/ssl_session_timeout/a\\    client_max_body_size 260m;', nginx_conf],
                capture_output=True, text=True, timeout=5,
            )
            changed = True

        if 'media/branding' not in content:
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
                capture_output=True, text=True, timeout=5,
            )
            changed = True

        if changed:
            subprocess.run(['sudo', '-n', 'nginx', '-t'], capture_output=True, text=True, timeout=5)
            subprocess.run(['sudo', '-n', 'nginx', '-s', 'reload'], capture_output=True, text=True, timeout=5)

        # Ensure media directories exist
        os.makedirs(os.path.join(base_dir, 'media', 'branding'), exist_ok=True)
        os.makedirs(os.path.join(base_dir, 'media', 'otf'), exist_ok=True)

    except Exception:
        pass  # Don't crash the app if Nginx patching fails


def ensure_superuser_group(sender, **kwargs):
    """Ensure the Superuser group exists with all app permissions. Sync is_superuser/is_staff flags with group membership."""
    from django.contrib.auth.models import Group, Permission
    from django.contrib.contenttypes.models import ContentType

    group, _ = Group.objects.get_or_create(name='Superuser')

    # Assign all app-relevant permissions
    app_content_types = ContentType.objects.filter(app_label__in=['app', 'users'])
    all_perms = Permission.objects.filter(content_type__in=app_content_types)
    group.permissions.set(all_perms)

    # Sync: users with is_superuser=True get added to the group
    User = __import__('users.models', fromlist=['CustomUser']).CustomUser
    for user in User.objects.filter(is_superuser=True):
        if not user.groups.filter(id=group.id).exists():
            user.groups.add(group)

    # Sync: users in the Superuser group get is_superuser=True, is_staff=True
    for user in group.user_set.all():
        if not user.is_superuser or not user.is_staff:
            user.is_superuser = True
            user.is_staff = True
            user.save(update_fields=['is_superuser', 'is_staff'])

    # Sync: users NOT in the Superuser group lose is_superuser/is_staff
    for user in User.objects.filter(is_superuser=True).exclude(groups=group):
        user.is_superuser = False
        user.is_staff = False
        user.save(update_fields=['is_superuser', 'is_staff'])
