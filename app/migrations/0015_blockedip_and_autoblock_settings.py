from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('app', '0014_appsettings_deployment_mode'),
    ]

    operations = [
        migrations.CreateModel(
            name='BlockedIP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(unique=True)),
                ('reason', models.CharField(blank=True, max_length=255)),
                ('blocked_at', models.DateTimeField(auto_now_add=True)),
                ('auto_blocked', models.BooleanField(default=False)),
                ('expires_at', models.DateTimeField(blank=True, null=True, verbose_name='Expires At')),
                ('blocked_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL, verbose_name='Blocked By')),
            ],
            options={
                'verbose_name': 'Blocked IP',
                'verbose_name_plural': 'Blocked IPs',
                'ordering': ['-blocked_at'],
            },
        ),
        migrations.AddField(
            model_name='appsettings',
            name='autoblock_enabled',
            field=models.BooleanField(default=False, verbose_name='Enable Auto-Block'),
        ),
        migrations.AddField(
            model_name='appsettings',
            name='autoblock_threshold',
            field=models.PositiveIntegerField(default=50, verbose_name='Auto-Block Threshold (requests)'),
        ),
        migrations.AddField(
            model_name='appsettings',
            name='autoblock_window_seconds',
            field=models.PositiveIntegerField(default=60, verbose_name='Auto-Block Window (seconds)'),
        ),
        migrations.AddField(
            model_name='appsettings',
            name='autoblock_duration_minutes',
            field=models.PositiveIntegerField(default=0, verbose_name='Auto-Block Duration (minutes, 0=permanent)'),
        ),
    ]
