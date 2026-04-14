from django.db import migrations
import app.crypto


def encrypt_existing(apps, schema_editor):
    AppSettings = apps.get_model('app', 'AppSettings')
    for s in AppSettings.objects.all():
        value = s.resend_api_key or ''
        if not value or app.crypto.is_encrypted(value):
            continue
        # Bypass the field's get_prep_value (historical models use a plain CharField
        # during migrations) by writing the ciphertext directly.
        AppSettings.objects.filter(pk=s.pk).update(
            resend_api_key=app.crypto.encrypt(value)
        )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0028_failed_login_block'),
    ]

    operations = [
        migrations.AlterField(
            model_name='appsettings',
            name='resend_api_key',
            field=app.crypto.EncryptedCharField(blank=True, default='', max_length=512, verbose_name='Resend API Key'),
        ),
        migrations.RunPython(encrypt_existing, noop_reverse),
    ]
