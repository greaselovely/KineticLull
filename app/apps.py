from django.apps import AppConfig


class EdlConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app'

    def ready(self):
        from django.db.models.signals import post_migrate
        post_migrate.connect(ensure_superuser_group, sender=self)


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
