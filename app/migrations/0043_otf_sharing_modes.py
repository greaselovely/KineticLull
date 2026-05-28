"""OTF sharing modes: secure (multi-recipient) and casual (self-attested).

Adds mode/max_downloads/casual_token/send_email/intended_recipients to
OneTimeFile, splits OTP state into per-recipient (OTFRecipient) and
per-session (OTFSession) tables, and introduces OTFDownload as the
per-delivery audit log. Existing rows become single-recipient secure
shares; their original token is reused on the backfilled OTFRecipient so
in-flight emailed URLs (/f/<token>/) keep resolving.

Forward-only: removing the legacy otp / otp_created_at columns drops
in-flight OTP state, so do not reverse this migration in production.
"""

from django.db import migrations, models


def backfill_recipients(apps, schema_editor):
    OneTimeFile = apps.get_model('app', 'OneTimeFile')
    OTFRecipient = apps.get_model('app', 'OTFRecipient')
    for f in OneTimeFile.objects.all():
        OTFRecipient.objects.create(
            file=f,
            email=f.recipient_email,
            token=f.token,
            otp=f.otp or '',
            otp_created_at=f.otp_created_at,
            downloaded=f.downloaded,
            downloaded_at=f.downloaded_at,
            burned=f.burned,
        )


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0042_alter_appsettings_robots_txt'),
    ]

    operations = [
        migrations.AddField(
            model_name='onetimefile',
            name='mode',
            field=models.CharField(
                choices=[('secure', 'Secure'), ('casual', 'Casual')],
                db_default='secure',
                default='secure',
                max_length=10,
            ),
        ),
        migrations.AddField(
            model_name='onetimefile',
            name='max_downloads',
            field=models.PositiveIntegerField(db_default=1, default=1),
        ),
        migrations.AddField(
            model_name='onetimefile',
            name='casual_token',
            field=models.CharField(blank=True, max_length=64, null=True, unique=True),
        ),
        migrations.AddField(
            model_name='onetimefile',
            name='send_email',
            field=models.BooleanField(db_default=True, default=True),
        ),
        migrations.AddField(
            model_name='onetimefile',
            name='intended_recipients',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.CreateModel(
            name='OTFRecipient',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('token', models.CharField(blank=True, max_length=64, unique=True)),
                ('otp', models.CharField(blank=True, max_length=6)),
                ('otp_created_at', models.DateTimeField(blank=True, null=True)),
                ('downloaded', models.BooleanField(default=False)),
                ('downloaded_at', models.DateTimeField(blank=True, null=True)),
                ('burned', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('file', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='recipients', to='app.onetimefile')),
            ],
            options={
                'ordering': ['created_at'],
                'unique_together': {('file', 'email')},
            },
        ),
        migrations.CreateModel(
            name='OTFSession',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('otp', models.CharField(blank=True, max_length=6)),
                ('otp_created_at', models.DateTimeField(blank=True, null=True)),
                ('verified_at', models.DateTimeField(blank=True, null=True)),
                ('download_count', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('file', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='sessions', to='app.onetimefile')),
            ],
            options={
                'ordering': ['created_at'],
                'unique_together': {('file', 'email')},
            },
        ),
        migrations.CreateModel(
            name='OTFDownload',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.CharField(blank=True, max_length=512)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('file', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='downloads', to='app.onetimefile')),
                ('recipient', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, related_name='downloads', to='app.otfrecipient')),
                ('session', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, related_name='downloads', to='app.otfsession')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.RunPython(backfill_recipients, noop),
        migrations.RemoveField(model_name='onetimefile', name='otp'),
        migrations.RemoveField(model_name='onetimefile', name='otp_created_at'),
    ]
