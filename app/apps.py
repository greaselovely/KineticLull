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
        _start_daily_backup_scheduler()
        _patch_nginx_config()
        _regenerate_blocklist()


def _regenerate_blocklist():
    """Regenerate deploy/blocklist.conf from BlockedIP rows on startup.

    The file is NOT tracked in git (it's operator state that varies per install).
    Re-creating it on every boot guarantees it exists after a pull that would
    otherwise have removed the working-tree copy — nginx `include`s it and will
    fail to start if it's missing.

    Guarantees the file exists even if the DB isn't ready (e.g., during
    migrations) by writing an empty file first, then attempting the sync.
    """
    import os
    from django.conf import settings

    blocklist_path = os.path.join(settings.BASE_DIR, 'deploy', 'blocklist.conf')
    try:
        os.makedirs(os.path.dirname(blocklist_path), exist_ok=True)
        if not os.path.exists(blocklist_path):
            with open(blocklist_path, 'w') as f:
                pass  # empty file — valid nginx include target
    except Exception:
        pass

    try:
        from app.models import BlockedIP
        BlockedIP.sync_to_nginx()
    except Exception:
        pass  # DB may not be ready yet (e.g., mid-migration); empty file is enough


_scheduler_lock_fd = None  # module-level: keep the lock fd alive for the process lifetime


def _acquire_scheduler_lock():
    """Acquire an exclusive flock so only one gunicorn worker runs the scheduled threads.

    Without this, every worker spawns its own backup/cleanup/parser loops and we
    end up with N copies of every scheduled action (3 identical B2 uploads at the
    same timestamp under default `--workers 3`, etc.). The lock is released by
    the kernel when the holding process dies, so a worker restart re-elects.
    """
    global _scheduler_lock_fd
    if _scheduler_lock_fd is not None:
        return True

    import os
    import fcntl
    from django.conf import settings

    lock_path = os.path.join(settings.BASE_DIR, 'backups', '.scheduler.lock')
    try:
        os.makedirs(os.path.dirname(lock_path), exist_ok=True)
        fd = open(lock_path, 'w')
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        try:
            fd.close()
        except Exception:
            pass
        return False

    _scheduler_lock_fd = fd  # keep alive for process lifetime
    return True


def _start_daily_backup_scheduler():
    """Run data backup daily in a background thread. Only starts once."""
    import threading
    import time
    import os

    # Don't run in manage.py commands (migrate, collectstatic, etc.)
    # Only run in the main gunicorn/runserver process
    if os.environ.get('RUN_MAIN') == 'true' or 'gunicorn' in os.environ.get('SERVER_SOFTWARE', ''):
        pass  # OK to run
    elif 'gunicorn' in (os.environ.get('_', '') or ''):
        pass  # Also OK
    else:
        return

    # Under gunicorn we have N workers, each calling ready(). Only the first
    # worker to grab the lock runs the schedulers; the others bail silently.
    if not _acquire_scheduler_lock():
        return

    def _backup_loop():
        """Run the daily backup at the configured local time-of-day.

        Computes the next run target each pass and sleeps up to 1 hour at a
        time so changes to the configured time take effect within the hour.
        """
        from datetime import datetime, time as dtime, timedelta
        try:
            from zoneinfo import ZoneInfo
        except ImportError:
            ZoneInfo = None

        time.sleep(60)  # startup grace
        last_run_date = None

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
    """Patch Nginx config on startup if needed — adds media/branding and client_max_body_size."""
    import subprocess
    import os
    from django.conf import settings

    # Only run in gunicorn/runserver, not manage.py commands
    if not (os.environ.get('RUN_MAIN') == 'true' or 'gunicorn' in (os.environ.get('SERVER_SOFTWARE', '') + os.environ.get('_', ''))):
        return

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
