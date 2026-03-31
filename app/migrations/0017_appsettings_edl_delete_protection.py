from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0016_nginxrejection'),
    ]

    operations = [
        migrations.AddField(
            model_name='appsettings',
            name='edl_delete_protection',
            field=models.BooleanField(default=True, verbose_name='Enable Active EDL Delete Protection'),
        ),
        migrations.AddField(
            model_name='appsettings',
            name='edl_delete_threshold',
            field=models.PositiveIntegerField(default=3, verbose_name='Min accesses to protect'),
        ),
        migrations.AddField(
            model_name='appsettings',
            name='edl_delete_window_minutes',
            field=models.PositiveIntegerField(default=15, verbose_name='Protection window (minutes)'),
        ),
    ]
