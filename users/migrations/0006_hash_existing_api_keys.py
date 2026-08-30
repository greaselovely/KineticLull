"""Convert stored plaintext API keys to SHA-256 digests.

Existing keys keep working: we hash what is already on disk, so deployed
GhostHunter installs and customer scripts authenticate unchanged. What is
lost is the ability to *read* a key back out, which is the point.

Every migrated key gets the wildcard scope. Narrowing them is an operator
decision, not something a migration should do silently to credentials that
are already in the field.

Note for upgrades: workers still running pre-hash code look keys up by the
plaintext column, which this migration blanks. Between `migrate` and the
service restart, those workers reject API calls with 401. The window is
seconds and clients retry, but it is why an upgrade is not a no-op for API
traffic.
"""

import hashlib

from django.db import migrations


def hash_existing(apps, schema_editor):
    APIKey = apps.get_model('users', 'APIKey')
    for api_key in APIKey.objects.all():
        raw = (api_key.key or '').strip()
        if not raw:
            continue
        APIKey.objects.filter(pk=api_key.pk).update(
            key_hash=hashlib.sha256(raw.encode('utf-8')).hexdigest(),
            key_prefix=raw[:12],
            scopes=['*'],
            key='',
        )


def noop_reverse(apps, schema_editor):
    """Irreversible by design: the plaintext is gone and cannot be rebuilt."""
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0005_apikey_hash_scopes'),
    ]

    operations = [
        migrations.RunPython(hash_existing, noop_reverse),
    ]
