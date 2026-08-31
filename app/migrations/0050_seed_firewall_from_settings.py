"""Carry the single configured firewall into the Firewall registry.

Before this, User-ID push had exactly one destination, stored on the
AppSettings singleton. The registry replaces that, so an install that is
already pushing must come out the other side still pushing, with no operator
action and no gap.

The API key moves across as ciphertext. Historical models use a plain
CharField during migrations, so reading `panos_api_key` here yields the stored
`enc:v1:` string rather than plaintext, and writing it straight through keeps
it that way. Encrypting again would double-wrap it.
"""

from django.db import migrations


def seed_firewall(apps, schema_editor):
    AppSettings = apps.get_model('app', 'AppSettings')
    Firewall = apps.get_model('app', 'Firewall')

    settings_row = AppSettings.objects.filter(pk=1).first()
    if not settings_row:
        return

    host = (settings_row.panos_host or '').strip()
    if not host:
        return

    if Firewall.objects.filter(address=host).exists():
        return

    Firewall.objects.create(
        name='Primary Firewall',
        vendor='panos',
        address=host,
        api_key=settings_row.panos_api_key or '',
        vsys=settings_row.panos_vsys or '',
        verify_ssl=settings_row.panos_verify_ssl,
        # This box was the push target by definition, so preserve that.
        receives_user_id=True,
        enabled=True,
        notes='Created automatically from the previous single-firewall setting.',
        last_push_at=settings_row.panos_last_push_at,
        last_push_status=settings_row.panos_last_push_status or '',
        last_push_error=settings_row.panos_last_push_error or '',
        last_push_count=settings_row.panos_last_push_count or 0,
    )


def unseed(apps, schema_editor):
    """Reverse by removing only the row this migration created."""
    Firewall = apps.get_model('app', 'Firewall')
    Firewall.objects.filter(
        name='Primary Firewall',
        notes='Created automatically from the previous single-firewall setting.',
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0049_firewall_registry'),
    ]

    operations = [
        migrations.RunPython(seed_firewall, unseed),
    ]
