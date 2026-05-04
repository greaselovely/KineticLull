"""
Backward-compatibility data migration. The 0003 migration introduced the
`users.use_api_key` permission. Without this step, every non-superuser who
already had an API key would lose UI access to it on the next deploy
(their key still validates, but they can't view or regenerate it).

This grants the new permission to any group whose members currently have
an APIKey row, preserving existing behavior. Idempotent.
"""

from django.contrib.auth.management import create_permissions
from django.db import migrations


def grant_use_api_key_to_holder_groups(apps, schema_editor):
    # Permissions are populated by a post_migrate signal that fires AFTER all
    # migrations in this run; force-create them now so we can reference the
    # new one inside this RunPython block.
    for app_config in apps.get_app_configs():
        app_config.models_module = True
        create_permissions(app_config, apps=apps, verbosity=0)
        app_config.models_module = None

    Permission = apps.get_model('auth', 'Permission')
    Group = apps.get_model('auth', 'Group')
    APIKey = apps.get_model('users', 'APIKey')

    perm = Permission.objects.filter(
        codename='use_api_key',
        content_type__app_label='users',
    ).first()
    if perm is None:
        return  # permission didn't get created — nothing to do

    holder_user_ids = set(APIKey.objects.values_list('user_id', flat=True))
    if not holder_user_ids:
        return

    for group in Group.objects.all():
        member_ids = set(group.user_set.values_list('id', flat=True))
        if member_ids & holder_user_ids:
            group.permissions.add(perm)


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_alter_apikey_options'),
    ]

    operations = [
        migrations.RunPython(grant_use_api_key_to_holder_groups, noop),
    ]
